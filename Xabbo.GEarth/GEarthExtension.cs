using System;
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
using System.ComponentModel;
using System.Runtime.CompilerServices;

using Microsoft.Extensions.Configuration;

using Xabbo.Messages;
using Xabbo.Interceptor;
using Xabbo.Interceptor.Dispatcher;

namespace Xabbo.GEarth
{
    /// <summary>
    /// A <see cref="IRemoteInterceptor"/> implementation for G-Earth extensions.
    /// </summary>
    public class GEarthExtension : IRemoteInterceptor, INotifyPropertyChanged
    {
        private const int
            DEFAULT_PORT = 9092,
            CONNECT_INTERVAL = 1000;

        private static readonly Encoding _encoding = Encoding.Latin1;
        private static readonly byte[]
            _toClientBytes = _encoding.GetBytes("TOCLIENT"),
            _toServerBytes = _encoding.GetBytes("TOSERVER");

        private enum GIncoming : short
        {
            Click = 1,
            InfoRequest = 2,
            PacketIntercept = 3,
            FlagsCheck = 4,
            ConnectionStart = 5,
            ConnectionEnd = 6,
            Init = 7,

            PacketToStringResponse = 20,
            StringToPacketResponse = 21
        }

        private enum GOutgoing : short
        {
            Info = 1,
            ManipulatedPacket = 2,
            RequestFlags = 3,
            SendMessage = 4,

            PacketToStringRequest = 20,
            StringToPacketRequest = 21,

            ExtensionConsoleLog = 98
        }

        protected bool Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
            {
                return false;
            }
            else
            {
                field = value;
                RaisePropertyChanged(propertyName);
                return true;
            }
        }

        protected virtual void RaisePropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private readonly SemaphoreSlim _sendSemaphore = new(1, 1);

        private TcpClient? _client;
        private NetworkStream? _ns;

        private CancellationTokenSource? _cancellation;

        public event EventHandler? InterceptorConnected;
        protected virtual void OnInterceptorConnected() => InterceptorConnected?.Invoke(this, EventArgs.Empty);

        public event EventHandler? InterceptorDisconnected;
        protected virtual void OnInterceptorDisconnected() => InterceptorDisconnected?.Invoke(this, EventArgs.Empty);

        public event EventHandler<InterceptorInitializedEventArgs>? Initialized;
        protected virtual void OnInitialized(InterceptorInitializedEventArgs e) => Initialized?.Invoke(this, e);

        public event EventHandler<GameConnectedEventArgs>? Connected;
        protected virtual void OnConnected(GameConnectedEventArgs e) => Connected?.Invoke(this, e);

        public event EventHandler? Disconnected;
        protected virtual void OnDisconnected() => Disconnected?.Invoke(this, EventArgs.Empty);

        public event EventHandler<InterceptArgs>? Intercepted;
        protected virtual void OnIntercepted(InterceptArgs e) => Intercepted?.Invoke(this, e);

        public event EventHandler? Clicked;
        protected virtual void OnClicked() => Clicked?.Invoke(this, EventArgs.Empty);

        public int Port { get; private set; }
        public GEarthOptions Options { get; }

        public IMessageManager Messages { get; }
        public IInterceptDispatcher Dispatcher { get; }
        public string ClientIdentifier { get; private set; } = string.Empty;
        public ClientType ClientType { get; private set; }

        private bool _isRunning;
        public bool IsRunning
        {
            get => _isRunning;
            set => Set(ref _isRunning, value);
        }

        private bool _isInterceptorConnected;
        public bool IsInterceptorConnected
        {
            get => _isInterceptorConnected;
            set => Set(ref _isInterceptorConnected, value);
        }

        private bool _isConnected;
        public bool IsConnected
        {
            get => _isConnected;
            set => Set(ref _isConnected, value);
        }

        public Incoming In => Messages.In;
        public Outgoing Out => Messages.Out;

        public void Send(Header header, params object[] values) => SendAsync(header, values);
        public void Send(IReadOnlyPacket packet) => SendAsync(packet);
        public Task SendAsync(Header header, params object[] values) => ForwardPacketAsync(Packet.Compose(ClientType, header, values));
        public Task SendAsync(IReadOnlyPacket packet) => ForwardPacketAsync(packet);

        public GEarthExtension(IConfiguration config, IMessageManager messages, GEarthOptions options)
        {
            Messages = messages;
            Options = options;

            Port = config.GetValue("Interceptor:Port", DEFAULT_PORT);

            Dispatcher = new InterceptDispatcher(messages);
        }

        public GEarthExtension(IMessageManager messages, GEarthOptions options, int port)
        {
            Messages = messages;
            Options = options;

            Port = port;

            Dispatcher = new InterceptDispatcher(messages);
        }

        public GEarthExtension(GEarthOptions options, int port)
        {
            Messages = new UnifiedMessageManager("messages.ini");
            Options = options;

            Port = port;

            Dispatcher = new InterceptDispatcher(Messages);
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

                IsInterceptorConnected = true;
                OnInterceptorConnected();

                Pipe pipe = new();
                await Task.WhenAll(
                    FillPipeAsync(_ns = _client.GetStream(), pipe.Writer),
                    ProcessPipeAsync(pipe.Reader)
                );
            }
            finally
            {
                if (IsInterceptorConnected)
                {
                    if (IsConnected)
                    {
                        IsConnected = false;
                        OnDisconnected();
                    }

                    IsInterceptorConnected = false;
                    OnInterceptorDisconnected();
                }

                IsRunning = false;
                Dispatcher.ReleaseAll();

                _client?.Close();
                _client = null;
                _ns = null;
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
            return ((GIncoming)packet.Header.Value) switch
            {
                GIncoming.Click => OnClick(packet),
                GIncoming.InfoRequest => OnInfoRequest(packet),
                GIncoming.PacketIntercept => OnPacketIntercept(packet),
                GIncoming.FlagsCheck => OnFlagsCheck(packet),
                GIncoming.ConnectionStart => OnConnectionStart(packet),
                GIncoming.ConnectionEnd => OnConnectionEnd(packet),
                GIncoming.Init => OnInit(packet),
                _ => Task.CompletedTask
            };
        }

        private Task OnClick(IReadOnlyPacket packet)
        {
            OnClicked();
            return Task.CompletedTask;
        }

        private Task OnInfoRequest(IReadOnlyPacket packet)
        {
            return SendInternalAsync(
                Packet.Compose((short)GOutgoing.Info,
                    Options.Title,
                    Options.Author,
                    Options.Version,
                    Options.Description,
                    Options.ShowEventButton,
                    !string.IsNullOrWhiteSpace(Options.FilePath),
                    Options.FilePath,
                    Options.Cookie,
                    Options.ShowLeaveButton,
                    Options.ShowDeleteButton
                )
            );
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

            var response = new Packet((short)GOutgoing.ManipulatedPacket);

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
            Dispatcher.Bind(this);

            IsConnected = true;
            OnConnected(new GameConnectedEventArgs()
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
            OnDisconnected();
            
            return Task.CompletedTask;
        }

        private Task OnInit(IReadOnlyPacket packet)
        {
            bool? isGameConnected = packet.Available > 0 ? packet.ReadBool() : null;

            Initialized?.Invoke(this, new InterceptorInitializedEventArgs(isGameConnected));
            return Task.CompletedTask;
        }

        private Task ForwardPacketAsync(IReadOnlyPacket packet)
        {
            if (!IsConnected) return Task.CompletedTask;

            if (packet.Header.Destination != Destination.Client &&
                packet.Header.Destination != Destination.Server)
            {
                throw new InvalidOperationException("Unknown packet destination.");
            }

            return SendInternalAsync(
                new Packet((short)GOutgoing.SendMessage)
                    .WriteByte(packet.Header.Destination == Destination.Server ? 1 : 0)
                    .WriteInt(6 + packet.Length) // length of (packet length + header + data)
                    .WriteInt(2 + packet.Length) // length of (header + data)
                    .WriteShort(packet.Header)
                    .WriteBytes(packet.GetBuffer().Span)
            );
        }

        private async Task SendInternalAsync(IReadOnlyPacket packet)
        {
            NetworkStream? ns = _ns;
            if (ns is null) return;

            Memory<byte> buffer = new byte[6];
            BinaryPrimitives.WriteInt32BigEndian(buffer.Span[0..4], 2 + packet.Length);
            BinaryPrimitives.WriteInt16BigEndian(buffer.Span[4..6], packet.Header);

            await _sendSemaphore.WaitAsync();
            try
            {
                await ns.WriteAsync(buffer[0..6]);
                await ns.WriteAsync(packet.GetBuffer());
            }
            finally { _sendSemaphore.Release(); }
        }
    }
}
