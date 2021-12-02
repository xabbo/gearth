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

using Xabbo.Messages;
using Xabbo.Interceptor;
using Xabbo.Interceptor.Dispatcher;
using Xabbo.Interceptor.Tasks;

namespace Xabbo.GEarth
{
    /// <summary>
    /// A <see cref="IRemoteInterceptor"/> implementation for G-Earth.
    /// </summary>
    public class GEarthExtension : IRemoteInterceptor, INotifyPropertyChanged
    {
        private const int CONNECT_INTERVAL = 1000;

        private static readonly byte[]
            _toClientBytes = Encoding.ASCII.GetBytes("TOCLIENT"),
            _toServerBytes = Encoding.ASCII.GetBytes("TOSERVER");

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

        private readonly int _remotePort;

        private readonly SemaphoreSlim _sendSemaphore = new(1, 1);
        private readonly Memory<byte> _buffer = new byte[6];

        private TcpClient? _tcpClient;
        private NetworkStream? _ns;

        private CancellationTokenSource? _cancellation;

        #region - Events -
        public event EventHandler<ConnectionFailedEventArgs>? InterceptorConnectionFailed;
        protected virtual void OnInterceptorConnectionFailed(ConnectionFailedEventArgs e)
            => InterceptorConnectionFailed?.Invoke(this, e);

        public event EventHandler? InterceptorConnected;
        protected virtual void OnInterceptorConnected() => InterceptorConnected?.Invoke(this, EventArgs.Empty);

        public event EventHandler<DisconnectedEventArgs>? InterceptorDisconnected;
        protected virtual void OnInterceptorDisconnected(DisconnectedEventArgs e)
            => InterceptorDisconnected?.Invoke(this, e);

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
        #endregion

        /// <summary>
        /// Gets the options used by this extension.
        /// </summary>
        public GEarthOptions Options { get; }

        /// <summary>
        /// Gets the message manager used by this extension.
        /// </summary>
        public IMessageManager Messages { get; }

        /// <summary>
        /// Gets the incoming headers from the message manager.
        /// </summary>
        public Incoming In => Messages.In;

        /// <summary>
        /// Gets the outgoing headers from the message manager.
        /// </summary>
        public Outgoing Out => Messages.Out;

        /// <summary>
        /// Gets the dispatcher responsible for routing intercepted messages.
        /// </summary>
        public IInterceptDispatcher Dispatcher { get; }

        private bool _isRunning;
        public bool IsRunning
        {
            get => _isRunning;
            private set => Set(ref _isRunning, value);
        }

        private bool _isInterceptorConnected;
        public bool IsInterceptorConnected
        {
            get => _isInterceptorConnected;
            private set => Set(ref _isInterceptorConnected, value);
        }

        private int _port;
        public int Port
        {
            get => _port;
            private set => Set(ref _port, value);
        }

        private bool _isConnected;
        public bool IsConnected
        {
            get => _isConnected;
            private set => Set(ref _isConnected, value);
        }

        private string _clientIdentifier = string.Empty;
        public string ClientIdentifier
        {
            get => _clientIdentifier;
            private set => Set(ref _clientIdentifier, value);
        }

        private ClientType _client = ClientType.Unknown;
        public ClientType Client
        {
            get => _client;
            private set => Set(ref _client, value);
        }

        public void Send(Header header, params object[] values) => SendAsync(header, values);
        public void Send(IReadOnlyPacket packet) => SendAsync(packet);
        public Task SendAsync(Header header, params object[] values) => ForwardPacketAsync(Packet.Compose(Client, header, values));
        public Task SendAsync(IReadOnlyPacket packet) => ForwardPacketAsync(packet);

        public Task<IPacket> ReceiveAsync(HeaderSet headers, int timeout = -1,
            bool block = false, CancellationToken cancellationToken = default)
        {
            return new CaptureMessageTask(this, headers, block)
                .ExecuteAsync(timeout, cancellationToken);
        }

        public Task<IPacket> ReceiveAsync(Header header, int timeout = -1,
            bool block = false, CancellationToken cancellationToken = default)
        {
            return new CaptureMessageTask(this, new[] { header }, block)
                .ExecuteAsync(timeout, cancellationToken);
        }

        public Task<IPacket> ReceiveAsync(ITuple headers, int timeout = -1,
            bool block = false, CancellationToken cancellationToken = default)
        {
            return new CaptureMessageTask(this, HeaderSet.FromTuple(headers), block)
                .ExecuteAsync(timeout, cancellationToken);
        }

        /// <summary>
        /// Creates a new <see cref="GEarthExtension"/> using the specified <see cref="IMessageManager"/> and <see cref="GEarthOptions"/>.
        /// </summary>
        /// <param name="messages">The message manager to be used by this extension.</param>
        /// <param name="options">The options to be used by this extension.</param>
        public GEarthExtension(IMessageManager messages, GEarthOptions options)
        {
            Messages = messages;
            Options = options;

            Dispatcher = new InterceptDispatcher(messages);
        }

        /// <summary>
        /// Creates a new <see cref="GEarthExtension"/> with the specified <see cref="GEarthOptions"/>.
        /// Uses a <see cref="UnifiedMessageManager"/> which loads a file named <c>messages.ini</c>.
        /// </summary>
        /// <param name="options">The options to be used by this extension.</param>
        public GEarthExtension(GEarthOptions options)
            : this(new UnifiedMessageManager("messages.ini"), options)
        { }

        public async Task RunAsync()
        {
            if (IsRunning)
                throw new InvalidOperationException("The interceptor service is already running.");

            _cancellation = new CancellationTokenSource();

            IsRunning = true;

            try
            {
                await Messages.InitializeAsync(_cancellation.Token).ConfigureAwait(false);
                await HandleInterceptorAsync(_cancellation.Token);
            }
            finally
            {
                Dispatcher.ReleaseAll();

                _tcpClient?.Close();
                _tcpClient = null;
                _ns = null;

                IsRunning = false;
            }
        }

        public void Stop()
        {
            if (!IsRunning) return;

            _cancellation?.Cancel();
            _cancellation = null;
        }

        private async Task HandleInterceptorAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Exception? error = null;

                try
                {
                    _tcpClient = await ConnectAsync(cancellationToken);
                    OnInterceptorConnected();

                    Pipe pipe = new();
                    await Task.WhenAll(
                        FillPipeAsync(_ns = _tcpClient.GetStream(), pipe.Writer, cancellationToken),
                        ProcessPipeAsync(pipe.Reader, cancellationToken)
                    );
                }
                catch (Exception ex)
                {
                    error = ex;
                }
                finally
                {
                    Dispatcher.ReleaseAll();
                    Port = 0;

                    _ns = null;
                    _tcpClient?.Close();
                    _tcpClient = null;
                }

                DisconnectedEventArgs disconnectedEventArgs = new(error);

                if (IsInterceptorConnected)
                {
                    if (IsConnected)
                    {
                        IsConnected = false;
                        OnDisconnected();
                    }

                    IsInterceptorConnected = false;
                    OnInterceptorDisconnected(disconnectedEventArgs);
                }

                if (!disconnectedEventArgs.Reconnect)
                {
                    if (error is not null)
                    {
                        throw error;
                    }

                    break;
                }
            }
        }

        private async Task<TcpClient> ConnectAsync(CancellationToken cancellationToken)
        {
            int attempt = 0;

            while (true)
            {
                attempt++;
                TcpClient client = new();

                try
                {
                    await client.ConnectAsync(IPAddress.Loopback, Options.Port, cancellationToken);

                    IsInterceptorConnected = true;
                    Port = Options.Port;

                    return client;
                }
                catch
                {
                    ConnectionFailedEventArgs e = new(attempt);
                    OnInterceptorConnectionFailed(e);

                    if (!e.Retry)
                        throw new Exception($"Failed to connect to G-Earth on port {Options.Port}.");
                }

                await Task.Delay(CONNECT_INTERVAL, cancellationToken);
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

        private static async Task FillPipeAsync(Stream stream, PipeWriter writer, CancellationToken cancellationToken)
        {
            Exception? error = null;

            while (true)
            {
                Memory<byte> memory = writer.GetMemory(1024);
                try
                {
                    int bytesRead = await stream.ReadAsync(memory, cancellationToken);
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

        private async Task ProcessPipeAsync(PipeReader reader, CancellationToken cancellationToken)
        {
            Exception? error = null;

            while (true)
            {
                ReadResult result = await reader.ReadAsync(cancellationToken);

                ReadOnlySequence<byte> buffer = result.Buffer;

                while (buffer.Length >= 4)
                {
                    int packetLength = ParsePacketLength(buffer);
                    if (buffer.Length < (4 + packetLength)) break;

                    buffer = buffer.Slice(4);
                    Header header = Header.In(ParsePacketHeader(buffer));

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
            return ((GIncoming)(packet.Header.Value ?? -1)) switch
            {
                GIncoming.Click => HandleClick(packet),
                GIncoming.InfoRequest => HandleInfoRequest(packet),
                GIncoming.PacketIntercept => HandlePacketIntercept(packet),
                GIncoming.FlagsCheck => HandleFlagsCheck(packet),
                GIncoming.ConnectionStart => HandleConnectionStart(packet),
                GIncoming.ConnectionEnd => HandleConnectionEnd(packet),
                GIncoming.Init => HandleInit(packet),
                _ => Task.CompletedTask
            };
        }

        private Task HandleClick(IReadOnlyPacket packet)
        {
            OnClicked();
            return Task.CompletedTask;
        }

        private Task HandleInfoRequest(IReadOnlyPacket packet)
        {
            return SendInternalAsync(
                Packet.Compose(
                    Header.Out((short)GOutgoing.Info),
                    Options.Name,
                    Options.Author,
                    Options.Version,
                    Options.Description,
                    Options.ShowEventButton,
                    Options.IsInstalledExtension,
                    Options.FileName,
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
            int index = int.Parse(Encoding.ASCII.GetString(span[(tabs[0] + 1)..tabs[1]]));
            bool isOutgoing = span[tabs[1] + 3] == 'S';
            bool isModified = span[tabs[2] + 1] == '1';

            Destination destination = isOutgoing ? Destination.Server : Destination.Client;

            ReadOnlySpan<byte> packetSpan = span[(tabs[2] + 2)..];
            short headerValue = BinaryPrimitives.ReadInt16BigEndian(packetSpan[4..6]);

            if (!Messages.TryGetHeaderByValue(destination, Client, headerValue, out Header? header))
            {
                header = new Header(destination, headerValue);
            }

            return new InterceptArgs(
                destination,
                Client,
                index,
                new Packet(Client, header, packetSpan[6..])
            );
        }

        private async Task HandlePacketIntercept(IReadOnlyPacket packet)
        {
            using InterceptArgs args = ParseInterceptArgs(packet);

            Intercepted?.Invoke(this, args);

            if (args.IsIncoming)
                Dispatcher.DispatchMessage(this, args.Packet);
            Dispatcher.DispatchIntercept(args);

            var response = new Packet(Header.Out((short)GOutgoing.ManipulatedPacket));

            response.WriteInt(-1);

            response.WriteByte((byte)(args.IsBlocked ? '1' : '0'));
            response.WriteByte(0x09);

            response.WriteBytes(Encoding.ASCII.GetBytes(args.Step.ToString()));
            response.WriteByte(0x09);

            response.WriteBytes(args.Destination == Destination.Client ? _toClientBytes : _toServerBytes);
            response.WriteByte(0x09);

            response.WriteByte((byte)((args.IsModified) ? '1' : '0'));
            response.WriteInt(2 + args.Packet.Length);
            response.WriteShort(args.Packet.Header.GetValue(Client));
            response.WriteBytes(args.Packet.GetBuffer().Span);

            response.Position = 0;
            response.WriteInt(response.Length - 4);

            await SendInternalAsync(response);
        }

        private Task HandleFlagsCheck(IReadOnlyPacket packet)
        {
            return Task.CompletedTask;
        }

        private Task HandleConnectionStart(IReadOnlyPacket packet)
        {
            string host = packet.ReadString();
            int port = packet.ReadInt();
            string clientVersion = packet.ReadString();
            ClientIdentifier = packet.ReadString();
            string clientType = packet.ReadString();

            if (clientType.StartsWith("Unity", StringComparison.OrdinalIgnoreCase)) Client = ClientType.Unity;
            else if (clientType.StartsWith("Flash", StringComparison.OrdinalIgnoreCase)) Client = ClientType.Flash;
            else Client = ClientType.Unknown;

            int n = packet.ReadInt();
            List<IClientMessageInfo> messages = new(n);
            for (int i = 0; i < n; i++)
            {
                int id = packet.ReadInt();
                string hash = packet.ReadString();
                string name = packet.ReadString();
                string structure = packet.ReadString();
                bool isOutgoing = packet.ReadBool();
                string source = packet.ReadString();

                messages.Add(new ClientMessageInfo
                {
                    Client = Client,
                    Direction = isOutgoing ? Direction.Outgoing : Direction.Incoming,
                    Header = (short)id,
                    Name = name
                });
            }

            Messages.LoadMessages(messages);
            Dispatcher.Bind(this, Client);

            IsConnected = true;
            OnConnected(new GameConnectedEventArgs()
            {
                Host = host,
                Port = port,
                ClientVersion = clientVersion,
                ClientIdentifier = ClientIdentifier,
                ClientType = Client,
                Messages = messages
            });

            return Task.CompletedTask;
        }

        private Task HandleConnectionEnd(IReadOnlyPacket packet)
        {
            IsConnected = false;
            Dispatcher.ReleaseAll();
            OnDisconnected();
            
            return Task.CompletedTask;
        }

        private Task HandleInit(IReadOnlyPacket packet)
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
                new Packet(Header.Out((short)GOutgoing.SendMessage))
                    .WriteByte((byte)(packet.Header.IsOutgoing ? 1 : 0))
                    .WriteInt(6 + packet.Length) // length of (packet length + header + data)
                    .WriteInt(2 + packet.Length) // length of (header + data)
                    .WriteShort(packet.Header.GetValue(Client))
                    .WriteBytes(packet.GetBuffer().Span)
            );
        }

        private async Task SendInternalAsync(IReadOnlyPacket packet)
        {
            NetworkStream? ns = _ns;
            if (ns is null) return;

            short headerValue = packet.Header.Value ?? throw new Exception("Invalid packet header.");

            await _sendSemaphore.WaitAsync();
            try
            {
                BinaryPrimitives.WriteInt32BigEndian(_buffer.Span[0..4], 2 + packet.Length);
                BinaryPrimitives.WriteInt16BigEndian(_buffer.Span[4..6], headerValue);
                await ns.WriteAsync(_buffer[0..6]);
                await ns.WriteAsync(packet.GetBuffer());
            }
            finally { _sendSemaphore.Release(); }
        }
    }
}
