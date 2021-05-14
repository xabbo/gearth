﻿using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.Extensions.Configuration;

using Xabbo.GEarth;
using Xabbo.Messages;
using Xabbo.Interceptor.Dispatcher;

namespace Xabbo.Interceptor.GEarth
{
    public class GEarthRemoteInterceptor : IRemoteInterceptor
    {
        private const int
            DEFAULT_PORT = 9092,
            CONNECT_INTERVAL = 1000;

        private static readonly Encoding _encoding = Encoding.Latin1;
        private static readonly byte[]
            _toClientBytes = _encoding.GetBytes("TOCLIENT"),
            _toServerBytes = _encoding.GetBytes("TOSERVER");

        public enum Incoming : short
        {
            DoubleClick = 1,
            InfoRequest = 2,
            PacketIntercept = 3,
            FlagsCheck = 4,
            ConnectionStart = 5,
            ConnectionEnd = 6,
            Init = 7,

            PacketToStringResponse = 20,
            StringToPacketResponse = 21
        }

        public enum Outgoing : short
        {
            Info = 1,
            ManipulatedPacket = 2,
            RequestFlags = 3,
            SendMessage = 4,

            PacketToStringRequest = 20,
            StringToPacketRequest = 21,

            ExtensionConsoleLog = 98
        }

        private TcpClient? _client;
        private NetworkStream? _ns;

        private CancellationTokenSource? _cancellation;

        public event EventHandler? InterceptorConnected;
        public event EventHandler? InterceptorDisconnected;
        public event EventHandler<InterceptorInitializedEventArgs>? Initialized;
        public event EventHandler<GameConnectedEventArgs>? Connected;
        public event EventHandler? Disconnected;
        public event EventHandler<InterceptArgs>? Intercepted;
        public event EventHandler? Clicked;

        public int Port { get; private set; }
        public GEarthOptions Options { get; }

        public IMessageManager Messages { get; }
        public IInterceptDispatcher Dispatcher { get; }
        public string ClientIdentifier { get; private set; } = string.Empty;
        public ClientType ClientType { get; private set; }

        public bool IsRunning { get; private set; }
        public bool IsInterceptorConnected { get; private set; }
        public bool IsConnected { get; private set; }

        public GEarthRemoteInterceptor(IConfiguration config, IMessageManager messages, GEarthOptions options)
        {
            Messages = messages;
            Options = options;

            Port = config.GetValue("Interceptor:Port", DEFAULT_PORT);

            Dispatcher = new InterceptDispatcher(messages);
        }

        public GEarthRemoteInterceptor(IMessageManager messages, GEarthOptions options, int port)
        {
            Messages = messages;
            Options = options;

            Port = port;

            Dispatcher = new InterceptDispatcher(messages);
        }

        public Task RunAsync()
        {
            if (IsRunning)
                throw new InvalidOperationException("The interceptor service is already running.");

            _cancellation = new CancellationTokenSource();
            return HandleInterceptorAsync(_cancellation.Token);
        }

        public void Stop()
        {
            if (!IsRunning) return;

            _cancellation?.Cancel();
            _cancellation = null;
        }

        private async Task HandleInterceptorAsync(CancellationToken cancellationToken)
        {
            try
            {
                IsRunning = true;

                _client = await ConnectAsync(cancellationToken);
                InterceptorConnected?.Invoke(this, EventArgs.Empty);

                Pipe pipe = new();
                await Task.WhenAll(
                    FillPipeAsync(_ns = _client.GetStream(), pipe.Writer),
                    ProcessPipeAsync(pipe.Reader)
                );
            }
            finally
            {
                IsRunning = false;

                Dispatcher.ReleaseAll();

                _client?.Close();
                _client = null;
                _ns = null;

                if (IsInterceptorConnected)
                {
                    IsInterceptorConnected = false;

                    if (IsConnected)
                    {
                        IsConnected = false;
                        Disconnected?.Invoke(this, EventArgs.Empty);
                    }

                    InterceptorDisconnected?.Invoke(this, EventArgs.Empty);
                }
            }
        }

        private async Task<TcpClient> ConnectAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                TcpClient client = new();

                try
                {
                    await client.ConnectAsync(IPAddress.Loopback, Port, cancellationToken);
                }
                catch
                {
                    await Task.Delay(CONNECT_INTERVAL, cancellationToken);
                    continue;
                }

                return client;
            }
        }

        private static int ParsePacketLength(in ReadOnlySequence<byte> buffer)
        {
            if (buffer.First.Length >= 4)
            {
                return BinaryPrimitives.ReadInt32BigEndian(buffer.First.Span);
            }
            else
            {
                Span<byte> stackBuffer = stackalloc byte[4];
                buffer.Slice(0, 4).CopyTo(stackBuffer);
                return BinaryPrimitives.ReadInt32BigEndian(stackBuffer);
            }
        }

        private static short ParsePacketHeader(in ReadOnlySequence<byte> buffer)
        {
            if (buffer.First.Length >= 2)
            {
                return BinaryPrimitives.ReadInt16BigEndian(buffer.First.Span);
            }
            else
            {
                Span<byte> stackBuffer = stackalloc byte[2];
                buffer.Slice(0, 2).CopyTo(stackBuffer);
                return BinaryPrimitives.ReadInt16BigEndian(stackBuffer);
            }
        }

        private static async Task FillPipeAsync(Stream stream, PipeWriter writer)
        {
            Exception? error = null;

            while (true)
            {
                Memory<byte> memory = writer.GetMemory(512);
                try
                {
                    int bytesRead = await stream.ReadAsync(memory);
                    if (bytesRead == 0) break;

                    writer.Advance(bytesRead);
                }
                catch (Exception ex)
                {
                    error = ex;
                    break;
                }

                FlushResult result = await writer.FlushAsync();
                if (result.IsCompleted) break;
            }

            await writer.CompleteAsync(error);
        }

        private async Task ProcessPipeAsync(PipeReader reader)
        {
            Exception? error = null;

            while (true)
            {
                ReadResult result = await reader.ReadAsync();

                ReadOnlySequence<byte> buffer = result.Buffer;

                while (buffer.Length >= 4)
                {
                    int packetLength = ParsePacketLength(buffer);
                    if (buffer.Length < (4 + packetLength)) break;

                    buffer = buffer.Slice(4);
                    short header = ParsePacketHeader(buffer);

                    Packet packet = new(header, buffer.Slice(2, packetLength - 2));

                    buffer = buffer.Slice(packetLength);

                    try
                    {
                        await HandlePacketAsync(packet);
                    }
                    catch (Exception ex)
                    {
                        error = ex;
                        break;
                    }
                }

                if (error is not null) break;

                reader.AdvanceTo(buffer.Start, buffer.End);

                if (result.IsCompleted) break;
            }

            await reader.CompleteAsync(error);
        }

        private Task HandlePacketAsync(IReadOnlyPacket packet)
        {
            return ((Incoming)packet.Header.Value) switch
            {
                Incoming.DoubleClick => OnDoubleClick(packet),
                Incoming.InfoRequest => OnInfoRequest(packet),
                Incoming.PacketIntercept => OnPacketIntercept(packet),
                Incoming.FlagsCheck => OnFlagsCheck(packet),
                Incoming.ConnectionStart => OnConnectionStart(packet),
                Incoming.ConnectionEnd => OnConnectionEnd(packet),
                Incoming.Init => OnInit(packet),
                _ => Task.CompletedTask
            };
        }

        private Task OnDoubleClick(IReadOnlyPacket packet)
        {
            Clicked?.Invoke(this, EventArgs.Empty);
            return Task.CompletedTask;
        }

        private Task OnInfoRequest(IReadOnlyPacket packet)
        {
            var response = new Packet((short)Outgoing.Info);

            response.WriteString(Options.Title);
            response.WriteString(Options.Author);
            response.WriteString(Options.Version);
            response.WriteString(Options.Description);
            response.WriteBool(Options.ShowEventButton);
            response.WriteBool(!string.IsNullOrWhiteSpace(Options.FilePath));
            response.WriteString(Options.FilePath);
            response.WriteString(Options.Cookie);
            response.WriteBool(Options.ShowLeaveButton);
            response.WriteBool(Options.ShowDeleteButton);

            return SendInternalAsync(response);
        }

        private InterceptArgs ParseInterceptArgs(IReadOnlyPacket packet)
        {
            const byte TAB = 0x09;

            ReadOnlySpan<byte> span = packet.GetBuffer().Span[4..];

            Span<int> tabs = stackalloc int[3];
            int current = 0;
            for (int i = 0; i < span.Length; i++)
            {
                if (span[i] == TAB)
                {
                    tabs[current++] = i;
                    if (current == tabs.Length)
                        break;
                }
            }

            if (current != tabs.Length)
                throw new InvalidOperationException("Invalid packet intercept data (insufficient delimiter bytes)");

            bool isBlocked = span[0] == '1';
            int index = int.Parse(_encoding.GetString(span[(tabs[0] + 1)..tabs[1]]));
            bool isOutgoing = span[tabs[1] + 3] == 'S';
            bool isModified = span[tabs[2] + 1] == '1';

            Destination destination = isOutgoing ? Destination.Server : Destination.Client;

            ReadOnlySpan<byte> packetSpan = span[(tabs[2] + 2)..];
            short headerValue = BinaryPrimitives.ReadInt16BigEndian(packetSpan[4..6]);

            if (!Messages.TryGetHeaderByValue(destination, headerValue, out Header? header))
            {
                header = new Header(destination, headerValue, null);
            }

            return new InterceptArgs(
                destination,
                ClientType,
                index,
                new Packet(ClientType, header, packetSpan[6..])
            );
        }

        private async Task OnPacketIntercept(IReadOnlyPacket packet)
        {
            using InterceptArgs args = ParseInterceptArgs(packet);

            Intercepted?.Invoke(this, args);

            if (args.IsIncoming)
                Dispatcher.DispatchMessage(this, args.Packet);
            Dispatcher.DispatchIntercept(args);

            var response = new Packet((short)Outgoing.ManipulatedPacket);

            response.WriteInt(-1);

            response.WriteByte((byte)(args.IsBlocked ? '1' : '0'));
            response.WriteByte(0x09);

            response.WriteBytes(_encoding.GetBytes(args.Step.ToString()));
            response.WriteByte(0x09);

            response.WriteBytes(args.Destination == Destination.Client ? _toClientBytes : _toServerBytes);
            response.WriteByte(0x09);

            response.WriteByte((byte)((args.IsModified) ? '1' : '0'));
            response.WriteInt(2 + args.Packet.Length);
            response.WriteShort(args.Packet.Header);
            response.WriteBytes(args.Packet.GetBuffer().Span);

            response.Position = 0;
            response.WriteInt(response.Length - 4);

            await SendInternalAsync(response);
        }

        private Task OnFlagsCheck(IReadOnlyPacket packet)
        {
            return Task.CompletedTask;
        }

        private Task OnConnectionStart(IReadOnlyPacket packet)
        {
            string host = packet.ReadString();
            int port = packet.ReadInt();
            string clientVersion = packet.ReadString();
            string clientIdentifier = packet.ReadString();
            string clientType = packet.ReadString();

            int n = packet.ReadInt();
            List<MessageInfo> messages = new(n);
            for (int i = 0; i < n; i++)
            {
                int id = packet.ReadInt();
                string hash = packet.ReadString();
                string name = packet.ReadString();
                string structure = packet.ReadString();
                bool isOutgoing = packet.ReadBool();
                string source = packet.ReadString();

                messages.Add(new MessageInfo
                {
                    Direction = isOutgoing ? Direction.Outgoing : Direction.Incoming,
                    Header = (short)id,
                    Name = name
                });
            }

            ClientIdentifier = clientIdentifier;

            if (clientType.StartsWith("Unity", StringComparison.OrdinalIgnoreCase)) ClientType = ClientType.Unity;
            else if (clientType.StartsWith("Flash", StringComparison.OrdinalIgnoreCase)) ClientType = ClientType.Flash;
            else ClientType = ClientType.Unknown;

            Messages.LoadMessages(ClientType, messages);

            IsConnected = true;

            Connected?.Invoke(this, new GameConnectedEventArgs()
            {
                Host = host,
                Port = port,
                ClientVersion = clientVersion,
                ClientIdentifier = clientIdentifier,
                ClientType = ClientType,
                Messages = messages
            });

            return Task.CompletedTask;
        }

        private Task OnConnectionEnd(IReadOnlyPacket packet)
        {
            IsConnected = false;
            Dispatcher.ReleaseAll();
            Disconnected?.Invoke(this, EventArgs.Empty);
            return Task.CompletedTask;
        }

        private Task OnInit(IReadOnlyPacket packet)
        {
            bool? isGameConnected = packet.Available > 0 ? packet.ReadBool() : null;

            Initialized?.Invoke(this, new InterceptorInitializedEventArgs(isGameConnected));
            return Task.CompletedTask;
        }

        private Task SendInternalAsync(IReadOnlyPacket packet)
        {
            Memory<byte> buffer = new byte[packet.Length + 6];
            BinaryPrimitives.WriteInt32BigEndian(buffer.Span[0..4], 2 + packet.Length);
            BinaryPrimitives.WriteInt16BigEndian(buffer.Span[4..6], packet.Header);
            packet.CopyTo(buffer.Span[6..]);

            NetworkStream? ns = _ns;

            if (ns is null)
            {
                return Task.CompletedTask;
            }
            else
            {
                return ns.WriteAsync(buffer).AsTask();
            }
        }

        public Task SendAsync(Header header, params object[] values)
        {
            return header.Destination switch
            {
                Destination.Client => SendToClientAsync(header, values),
                Destination.Server => SendToServerAsync(header, values),
                _ => throw new InvalidOperationException("Unknown header destination")
            };
        }

        public Task SendAsync(IReadOnlyPacket packet)
        {
            return packet.Header.Destination switch
            {
                Destination.Client => SendToClientAsync(packet),
                Destination.Server => SendToServerAsync(packet),
                _ => throw new InvalidOperationException("Unknown header destination")
            };
        }

        public Task SendToServerAsync(Header header, params object[] values) => SendToServerAsync(Packet.Compose(ClientType, header, values));
        public Task SendToServerAsync(IReadOnlyPacket packet) => SendToAsync(Destination.Server, packet);
        public Task SendToClientAsync(Header header, params object[] values) => SendToClientAsync(Packet.Compose(ClientType, header, values));
        public Task SendToClientAsync(IReadOnlyPacket packet) => SendToAsync(Destination.Client, packet);

        private Task SendToAsync(Destination destination, IReadOnlyPacket packet)
        {
            if (!IsConnected) return Task.CompletedTask;

            Packet requestPacket = new((short)Outgoing.SendMessage);
            requestPacket.WriteByte(destination == Destination.Server ? 1 : 0);
            requestPacket.WriteInt(6 + packet.Length); // Packet length (length + header + data)
            requestPacket.WriteInt(2 + packet.Length); // Packet length (header + data)
            requestPacket.WriteShort(packet.Header);
            requestPacket.WriteBytes(packet.GetBuffer().Span);

            return SendInternalAsync(requestPacket);
        }
    }
}
