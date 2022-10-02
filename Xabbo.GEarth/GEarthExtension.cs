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

using Xabbo.Common;
using Xabbo.Messages;
using Xabbo.Interceptor;
using Xabbo.Interceptor.Dispatcher;
using Xabbo.Interceptor.Tasks;

namespace Xabbo.GEarth
{
    /// <summary>
    /// A <see cref="IRemoteInterceptor"/> implementation for G-Earth.
    /// </summary>
    public class GEarthExtension : IRemoteInterceptor, IInterceptHandler, INotifyPropertyChanged
    {
        const byte TabChar = 0x09;
        const int ConnectInterval = 1000;

        private static readonly ReadOnlyMemory<byte>
            ToClientBytes = Encoding.ASCII.GetBytes("TOCLIENT"),
            ToServerBytes = Encoding.ASCII.GetBytes("TOSERVER");

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

        /// <summary>
        /// Sets the value of the specified field and raises the <see cref="PropertyChanged"/> event if the value was changed.
        /// </summary>
        /// <typeparam name="T">The type of the field.</typeparam>
        /// <param name="field">The backing field.</param>
        /// <param name="value">The value to set the field to.</param>
        /// <param name="propertyName">The name of the property used to access the backing field.</param>
        /// <returns><see langword="true"/> if the value of the field changed, otherwise <see langword="false"/>.</returns>
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

        /// <summary>
        /// Invokes <see cref="PropertyChanged"/> to notify listeners that a property on this instance has changed.
        /// </summary>
        /// <param name="propertyName">The name of the property that changed.</param>
        protected virtual void RaisePropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <inheritdoc />
        public event PropertyChangedEventHandler? PropertyChanged;

        private readonly SemaphoreSlim _sendSemaphore = new(1, 1);
        private readonly Memory<byte> _buffer = new byte[6];

        private TcpClient? _tcpClient;
        private NetworkStream? _ns;

        private CancellationTokenSource? _cancellation;

        private CancellationTokenSource _ctsDisconnect;

        /// <inheritdoc />
        public CancellationToken DisconnectToken { get; private set; }

        #region - Events -
        /// <inheritdoc />
        public event EventHandler<ConnectionFailedEventArgs>? InterceptorConnectionFailed;
        /// <inheritdoc cref="InterceptorConnectionFailed" />
        protected virtual void OnInterceptorConnectionFailed(ConnectionFailedEventArgs e)
            => InterceptorConnectionFailed?.Invoke(this, e);

        /// <inheritdoc />
        public event EventHandler? InterceptorConnected;
        /// <inheritdoc cref="InterceptorConnected" />
        protected virtual void OnInterceptorConnected() => InterceptorConnected?.Invoke(this, EventArgs.Empty);

        /// <inheritdoc />
        public event EventHandler<DisconnectedEventArgs>? InterceptorDisconnected;
        /// <inheritdoc cref="InterceptorDisconnected" />
        protected virtual void OnInterceptorDisconnected(DisconnectedEventArgs e)
            => InterceptorDisconnected?.Invoke(this, e);

        /// <inheritdoc />
        public event EventHandler<InterceptorInitializedEventArgs>? Initialized;
        /// <inheritdoc cref="Initialized" />
        protected virtual void OnInitialized(InterceptorInitializedEventArgs e) => Initialized?.Invoke(this, e);

        /// <inheritdoc />
        public event EventHandler<GameConnectedEventArgs>? Connected;
        /// <inheritdoc cref="Connected" />
        protected virtual void OnConnected(GameConnectedEventArgs e) => Connected?.Invoke(this, e);

        /// <inheritdoc />
        public event EventHandler? Disconnected;
        /// <inheritdoc cref="Disconnected" />
        protected virtual void OnDisconnected()
        {
            _ctsDisconnect.Cancel();
            _ctsDisconnect = new CancellationTokenSource();
            DisconnectToken = _ctsDisconnect.Token;

            Disconnected?.Invoke(this, EventArgs.Empty);
        }

        /// <inheritdoc />
        public event EventHandler<InterceptArgs>? Intercepted;
        /// <inheritdoc cref="Intercepted" />
        protected virtual void OnIntercepted(InterceptArgs e) => Intercepted?.Invoke(this, e);

        /// <summary>
        /// Invoked when the play button of this extension is clicked in the G-Earth user interface.
        /// </summary>
        public event EventHandler? Clicked;
        /// <inheritdoc cref="Clicked" />
        protected virtual void OnClicked() => Clicked?.Invoke(this, EventArgs.Empty);
        #endregion

        /// <summary>
        /// Gets the options used by this extension.
        /// </summary>
        public GEarthOptions Options { get; }

        /// <inheritdoc />
        public IMessageManager Messages { get; }

        /// <inheritdoc />
        public IInterceptDispatcher Dispatcher { get; }

        /// <summary>
        /// Gets the incoming headers from the message manager.
        /// </summary>
        public Incoming In => Messages.In;

        /// <summary>
        /// Gets the outgoing headers from the message manager.
        /// </summary>
        public Outgoing Out => Messages.Out;

        private bool _isRunning;
        /// <inheritdoc />
        public bool IsRunning
        {
            get => _isRunning;
            private set => Set(ref _isRunning, value);
        }

        private bool _isInterceptorConnected;
        /// <inheritdoc />
        public bool IsInterceptorConnected
        {
            get => _isInterceptorConnected;
            private set => Set(ref _isInterceptorConnected, value);
        }

        private int _port;
        /// <inheritdoc />
        public int Port
        {
            get => _port;
            private set => Set(ref _port, value);
        }

        private bool _isConnected;
        /// <inheritdoc />
        public bool IsConnected
        {
            get => _isConnected;
            private set => Set(ref _isConnected, value);
        }

        private string _clientIdentifier = string.Empty;
        /// <inheritdoc />
        public string ClientIdentifier
        {
            get => _clientIdentifier;
            private set => Set(ref _clientIdentifier, value);
        }

        private ClientType _client = ClientType.Unknown;
        /// <inheritdoc />
        public ClientType Client
        {
            get => _client;
            private set => Set(ref _client, value);
        }

        /// <inheritdoc />
        public ValueTask SendAsync(IReadOnlyPacket packet) => ForwardPacketAsync(packet);

        /// <inheritdoc />
        public void Send(IReadOnlyPacket packet) => ForwardPacket(packet);

        /// <inheritdoc />
        public Task<IPacket> ReceiveAsync(HeaderSet headers, int timeout = -1,
            bool block = false, CancellationToken cancellationToken = default)
        {
            return new CaptureMessageTask(this, headers, block)
                .ExecuteAsync(timeout, cancellationToken);
        }

        /// <inheritdoc />
        public Task<IPacket> ReceiveAsync(Header header, int timeout = -1,
            bool block = false, CancellationToken cancellationToken = default)
        {
            return new CaptureMessageTask(this, new[] { header }, block)
                .ExecuteAsync(timeout, cancellationToken);
        }

        /// <inheritdoc />
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
            _ctsDisconnect = new CancellationTokenSource();
            DisconnectToken = _ctsDisconnect.Token;

            Messages = messages;
            Options = options.WithExtensionAttributes(GetType());

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

        /// <inheritdoc />
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
                IsRunning = false;

                _cancellation?.Dispose();
                _cancellation = null;

                Dispatcher.ReleaseAll();

                _tcpClient?.Close();
                _tcpClient = null;
                _ns = null;
            }
        }

        /// <inheritdoc />
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

                await Task.Delay(ConnectInterval, cancellationToken);
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

                FlushResult result = await writer.FlushAsync(cancellationToken);
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

                    using Packet packet = new(header, buffer.Slice(2, packetLength - 2));

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

        private ValueTask HandlePacketAsync(IReadOnlyPacket packet)
        {
            return (GIncoming)(packet.Header.Value ?? -1) switch
            {
                GIncoming.Click => HandleClick(packet),
                GIncoming.InfoRequest => HandleInfoRequest(packet),
                GIncoming.PacketIntercept => HandlePacketIntercept(packet),
                GIncoming.FlagsCheck => HandleFlagsCheck(packet),
                GIncoming.ConnectionStart => HandleConnectionStart(packet),
                GIncoming.ConnectionEnd => HandleConnectionEnd(packet),
                GIncoming.Init => HandleInit(packet),
                _ => ValueTask.CompletedTask
            };
        }

        private ValueTask HandleClick(IReadOnlyPacket _)
        {
            OnClicked();
            return ValueTask.CompletedTask;
        }

        private async ValueTask HandleInfoRequest(IReadOnlyPacket _)
        {
            using Packet p = new(
                Header.Out((short)GOutgoing.Info),
                size:
                    16
                    + Options.Title.Length
                    + Options.Author.Length
                    + Options.Version.Length
                    + Options.Description.Length
                    + Options.FileName.Length
                    + Options.Cookie.Length
            );

            p
                .WriteString(Options.Title)
                .WriteString(Options.Author)
                .WriteString(Options.Version)
                .WriteString(Options.Description)
                .WriteBool(Options.ShowEventButton)
                .WriteBool(Options.IsInstalledExtension)
                .WriteString(Options.FileName)
                .WriteString(Options.Cookie)
                .WriteBool(Options.ShowLeaveButton)
                .WriteBool(Options.ShowDeleteButton);

            await SendInternalAsync(p);
        }

        /* int length
         * byte[length] intercepted packet info, a tab delimited "string" with 4 sections:
         *   1: whether the packet is blocked, either '0' or '1'
         *   2: an integer represented as a string, the index/sequence number of the packet
         *   3: the destination of the intercepted packet, either "TOCLIENT" or "TOSERVER"
         *   4: the packet data, which consists of:
         *     1: whether the packet has been modified by another extension, either '0' or '1'
         *     2: int length (of the 2-byte header + data)
         *     3: short header
         *     4: byte[] data
         */
        private InterceptArgs ParseInterceptArgs(IReadOnlyPacket packet)
        {
            ReadOnlySpan<byte> packetBuffer = packet.Buffer;

            int length = BinaryPrimitives.ReadInt32BigEndian(packetBuffer[0..4]);
            ReadOnlySpan<byte> data = packetBuffer[4..(4+length)];

            Span<int> tabs = stackalloc int[3];
            int current = 0;
            for (int i = 0; i < data.Length; i++)
            {
                if (data[i] == TabChar)
                {
                    tabs[current++] = i;
                    if (current == tabs.Length)
                        break;
                }
            }

            if (current != tabs.Length)
                throw new InvalidOperationException("Invalid packet intercept data (insufficient delimiter bytes).");

            bool isBlocked = data[0] == '1';
            int index = int.Parse(Encoding.ASCII.GetString(data[(tabs[0] + 1)..tabs[1]]));
            bool isOutgoing = data[tabs[1] + 3] == 'S';
            bool isModified = data[tabs[2] + 1] == '1';

            Destination destination = isOutgoing ? Destination.Server : Destination.Client;

            ReadOnlySpan<byte> packetSpan = data[(tabs[2] + 2)..];
            short headerValue = BinaryPrimitives.ReadInt16BigEndian(packetSpan[4..6]);

            if (!Messages.TryGetHeaderByValue(destination, Client, headerValue, out Header? header))
            {
                header = new Header(destination, headerValue);
            }

            return new InterceptArgs(this, destination, new Packet(header, packetSpan[6..], Client)) { Step = index };
        }

        private async ValueTask HandlePacketIntercept(IReadOnlyPacket packet)
        {
            using InterceptArgs args = ParseInterceptArgs(packet);

            Intercepted?.Invoke(this, args);

            if (args.IsIncoming)
                Dispatcher.DispatchMessage(this, args.Packet);
            Dispatcher.DispatchIntercept(args);

            string stepString = args.Step.ToString();
            int stepByteCount = Encoding.ASCII.GetByteCount(stepString);

            using Packet p = new(Header.Out((short)GOutgoing.ManipulatedPacket), size: 23 + stepByteCount + packet.Length);

            // length placeholder
            p.WriteInt(-1);

            // is blocked
            p.WriteByte((byte)(args.IsBlocked ? '1' : '0'));

            p.WriteByte(TabChar);

            // packet sequence number as a string
            Encoding.ASCII.GetBytes(stepString, p.GetSpan(stepByteCount));
            p.WriteByte(TabChar);

            // packet destination
            p.WriteBytes((args.Destination == Destination.Client ? ToClientBytes : ToServerBytes).Span);

            p.WriteByte(TabChar);

            // is modified
            p.WriteByte((byte)((args.IsModified) ? '1' : '0'));
            // header + packet length
            p.WriteInt(2 + args.Packet.Length);
            // packet header
            p.WriteShort(args.Packet.Header.GetValue(Client));
            // packet data
            p.WriteBytes(args.Packet.Buffer);

            p.Position = 0;
            p.WriteInt(p.Length - 4);

            await SendInternalAsync(p);
        }

        private ValueTask HandleFlagsCheck(IReadOnlyPacket _) => ValueTask.CompletedTask;

        private ValueTask HandleConnectionStart(IReadOnlyPacket packet)
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
                packet.Skip(packet.ReadShort()); // string hash = packet.ReadString();
                string name = packet.ReadString();
                packet.Skip(packet.ReadShort()); // string structure = packet.ReadString();
                bool isOutgoing = packet.ReadBool();
                packet.Skip(packet.ReadShort()); // string source = packet.ReadString();

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

            return ValueTask.CompletedTask;
        }

        private ValueTask HandleConnectionEnd(IReadOnlyPacket _)
        {
            IsConnected = false;
            Dispatcher.ReleaseAll();
            OnDisconnected();
            
            return ValueTask.CompletedTask;
        }

        private ValueTask HandleInit(IReadOnlyPacket packet)
        {
            bool? isGameConnected = packet.Available > 0 ? packet.ReadBool() : null;

            Initialized?.Invoke(this, new InterceptorInitializedEventArgs(isGameConnected));
            return ValueTask.CompletedTask;
        }

        /// <summary>
        /// Creates a packet that instructs G-Earth to forward the specified packet to the client or server.
        /// </summary>
        private IReadOnlyPacket CreateForwardingPacket(IReadOnlyPacket packet)
        {
            if (packet.Header.Destination != Destination.Client &&
                packet.Header.Destination != Destination.Server)
            {
                throw new InvalidOperationException("Unknown packet destination.");
            }

            return new Packet(Header.Out((short)GOutgoing.SendMessage), size: 11 + packet.Length)
                .WriteByte((byte)(packet.Header.IsOutgoing ? 1 : 0))
                .WriteInt(6 + packet.Length) // length of (packet length + header + data)
                .WriteInt(2 + packet.Length) // length of (header + data)
                .WriteShort(packet.Header.GetValue(Client))
                .WriteBytes(packet.Buffer);
        }

        /// <summary>
        /// Instructs G-Earth to forward the specified packet to the client or server.
        /// </summary>
        private void ForwardPacket(IReadOnlyPacket packet)
        {
            using IReadOnlyPacket p = CreateForwardingPacket(packet);

            SendInternal(p);
        }

        /// <summary>
        /// Instructs G-Earth to forward the specified packet to the client or server.
        /// </summary>
        private async ValueTask ForwardPacketAsync(IReadOnlyPacket packet)
        {
            using IReadOnlyPacket p = CreateForwardingPacket(packet);

            await SendInternalAsync(p);
        }

        /// <summary>
        /// Sends the specified packet to G-Earth.
        /// </summary>
        protected void SendInternal(IReadOnlyPacket packet)
        {
            NetworkStream? ns = _ns;
            if (ns is null) return;

            short headerValue = packet.Header.Value ?? throw new Exception("Invalid packet header.");

            _sendSemaphore.Wait();
            try
            {
                BinaryPrimitives.WriteInt32BigEndian(_buffer.Span[0..4], 2 + packet.Length);
                BinaryPrimitives.WriteInt16BigEndian(_buffer.Span[4..6], headerValue);
                ns.Write(_buffer.Span[0..6]);
                ns.Write(packet.Buffer);
            }
            finally { _sendSemaphore.Release(); }
        }

        /// <summary>
        /// Sends the specified packet to G-Earth.
        /// </summary>
        protected async ValueTask SendInternalAsync(IReadOnlyPacket packet)
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
                await ns.WriteAsync(packet.GetMemory());
            }
            finally { _sendSemaphore.Release(); }
        }
    }
}
