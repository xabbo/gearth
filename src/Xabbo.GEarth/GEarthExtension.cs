using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.IO.Hashing;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

using Xabbo.Messages;
using Xabbo.Extension;

namespace Xabbo.GEarth;

/// <summary>
/// A G-Earth extension protocol implementation.
/// </summary>
public partial class GEarthExtension : IRemoteExtension, INotifyPropertyChanged
{
    const int DefaultPort = 9092;
    const byte Tab = 0x09;

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

    private static int ToPacketFormat(Header header) => header.Client switch {
        ClientType.Shockwave => header.Direction switch {
            Direction.In => 1,
            Direction.Out => 2,
            _ => 0,
        },
        _ => 0,
    };

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
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    public event PropertyChangedEventHandler? PropertyChanged;

    private readonly SemaphoreSlim _runSemaphore = new(1, 1);
    private readonly SemaphoreSlim _sendSemaphore = new(1, 1);

    private TcpClient? _tcpClient;
    private NetworkStream? _ns;
    private GEarthConnectOptions _currentConnectOpts;

    private CancellationTokenSource? _cancellation;
    private CancellationTokenSource _ctsDisconnect = new CancellationTokenSource();
    public CancellationToken DisconnectToken => _ctsDisconnect.Token;

    #region - Events -
    public event Action<InitializedArgs>? Initialized;
    protected virtual void OnInitialized(InitializedArgs e) => Initialized?.Invoke(e);

    public event Action<GameConnectedArgs>? Connected;
    protected virtual void OnConnected(GameConnectedArgs e) => Connected?.Invoke(e);

    public event Action? Disconnected;
    protected virtual void OnDisconnected()
    {
        _ctsDisconnect.Cancel();
        _ctsDisconnect = new CancellationTokenSource();

        Disconnected?.Invoke();
    }

    public event InterceptCallback? Intercepted;
    protected virtual void OnIntercepted(Intercept e) => Intercepted?.Invoke(e);

    /// <summary>
    /// Invoked when the extension is selected in G-Earth's user interface.
    /// </summary>
    public event Action? Activated;
    protected virtual void OnActivated() => Activated?.Invoke();
    #endregion

    /// <summary>
    /// Gets the options used by this extension.
    /// </summary>
    public GEarthOptions Options { get; }

    public IMessageManager Messages { get; }
    public IMessageDispatcher Dispatcher { get; }

    private bool _isRunning;
    public bool IsRunning
    {
        get => _isRunning;
        private set => Set(ref _isRunning, value);
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

    private Session _session = Session.None;
    public Session Session
    {
        get => _session;
        private set => Set(ref _session, value);
    }

    /// <summary>
    /// Creates a new <see cref="GEarthExtension"/> with the specified <see cref="GEarthOptions"/>.
    /// </summary>
    /// <param name="messages">The message manager to use.</param>
    /// <param name="options">The options to be used by this extension.</param>
    public GEarthExtension(IMessageManager messages, GEarthOptions options)
    {
        Messages = messages;
        Dispatcher = new MessageDispatcher(this);

        if (this is IExtensionInfoInit init)
        {
            var info = init.Info;
            if (info.Name is not null)
                options = options with { Name = info.Name };
            if (info.Description is not null)
                options = options with { Description = info.Description };
            if (info.Author is not null)
                options = options with { Author = info.Author };
            if (info.Version is not null)
                options = options with { Version = info.Version };
        }

        Options = options;
    }

    /// <summary>
    /// Creates a new <see cref="GEarthExtension"/> with the specified <see cref="GEarthOptions"/>.
    /// Uses a <see cref="MessageManager"/> which loads a file named <c>messages.ini</c>.
    /// </summary>
    /// <param name="options">The options to be used by this extension.</param>
    public GEarthExtension(GEarthOptions options)
        : this(new MessageManager("messages.ini"), options)
    { }

    /// <summary>
    /// Creates a new <see cref="GEarthExtension"/> with the default options.
    /// </summary>
    public GEarthExtension()
        : this(GEarthOptions.Default)
    { }

    public Task RunAsync(CancellationToken cancellationToken) => RunAsync(default, cancellationToken);
    public async Task RunAsync(GEarthConnectOptions connectOpts = default, CancellationToken cancellationToken = default)
    {
        if (!_runSemaphore.Wait(0, cancellationToken))
            throw new InvalidOperationException("The extension is already running.");

        try
        {
            IsRunning = true;

            _currentConnectOpts = connectOpts.WithArgs(Environment.GetCommandLineArgs().AsSpan()[1..]);
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            await Messages.InitializeAsync(_cancellation.Token).ConfigureAwait(false);
            await HandleInterceptorAsync(_currentConnectOpts, _cancellation.Token);
        }
        finally
        {
            IsRunning = false;

            _cancellation?.Dispose();
            _cancellation = null;

            Dispatcher.Reset();

            _tcpClient?.Close();
            _tcpClient = null;
            _ns = null;

            _runSemaphore.Release();
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;

        _cancellation?.Cancel();
        _cancellation = null;
    }

    public void Send(IPacket packet)
    {
        if (packet.Header.Direction != Direction.In && packet.Header.Direction != Direction.Out)
            throw new InvalidOperationException("Invalid packet direction.");

        if (packet.Header.Client != Session.Client.Type)
            throw new InvalidOperationException($"Invalid client {packet.Header.Client} on header, must be same as session: {Session.Client.Type}.");

        using Packet p = new((Direction.Out, (short)GOutgoing.SendMessage), capacity: 11 + packet.Length);
        p.Write((byte)(packet.Header.Direction == Direction.Out ? 1 : 0));

        if (Session.Client.Type == ClientType.Shockwave)
        {
            // length of (header + data)
            p.Write(2 + packet.Length);
            B64.Encode(p.Buffer.Allocate(p.Position, 2), packet.Header.Value);
            p.Position += 2;
        }
        else
        {
            // length of (packet length + header + data)
            p.Write(6 + packet.Length);
            p.Write(2 + packet.Length); // length of (header + data)
            p.Write(packet.Header.Value);
        }
        p.WriteSpan(packet.Buffer.Span);
        p.Write(ToPacketFormat(packet.Header));
        SendInternal(p);
    }

    protected Task<IPacket> ReceiveAsync(ReadOnlySpan<Header> headers,
        int timeout = -1, bool block = false, Func<IPacket, bool>? shouldCapture = null,
        CancellationToken cancellationToken = default)
    {
        return InterceptorExtensions.ReceiveAsync(this,
            headers, timeout, block, shouldCapture, cancellationToken);
    }

    protected Task<IPacket> ReceiveAsync(ReadOnlySpan<Identifier> identifiers,
        int timeout = -1, bool block = false, Func<IPacket, bool>? shouldCapture = null,
        CancellationToken cancellationToken = default)
    {
        return InterceptorExtensions.ReceiveAsync(this,
            identifiers, timeout, block, shouldCapture, cancellationToken);
    }

    private async Task HandleInterceptorAsync(GEarthConnectOptions connectOpts, CancellationToken cancellationToken)
    {
        try
        {
            _tcpClient = await ConnectAsync(connectOpts, cancellationToken);

            Pipe pipe = new();
            await Task.WhenAll(
                FillPipeAsync(_ns = _tcpClient.GetStream(), pipe.Writer, cancellationToken),
                ProcessPipeAsync(pipe.Reader, cancellationToken)
            );
        }
        finally
        {
            _ns = null;
            _tcpClient?.Close();
            _tcpClient = null;

            Dispatcher.Reset();
            Port = 0;
            Session = Session.None;

            if (IsConnected)
            {
                IsConnected = false;
                OnDisconnected();
            }
        }
    }

    private async Task<TcpClient> ConnectAsync(GEarthConnectOptions connectInfo, CancellationToken cancellationToken)
    {
        string host = connectInfo.Host ?? "127.0.0.1";
        int port = connectInfo.Port ?? DefaultPort;

        try
        {
            TcpClient client = new();
            await client.ConnectAsync(host, port, cancellationToken);
            Port = port;
            return client;
        }
        catch (SocketException)
        {
            throw new Exception($"Failed to connect to G-Earth on {host}:{port}.");
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
        const int minimumBufferSize = 4096;

        Exception? error = null;

        while (true)
        {
            Memory<byte> memory = writer.GetMemory(minimumBufferSize);
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
                Header header = (Direction.In, ParsePacketHeader(buffer));

                using Packet packet = new(header, buffer.Slice(2, packetLength - 2));

                buffer = buffer.Slice(packetLength);

                try { HandlePacket(packet); }
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

    private void HandlePacket(Packet packet)
    {
        switch ((GIncoming)packet.Header.Value)
        {
            case GIncoming.Click: HandleClick(packet); break;
            case GIncoming.InfoRequest: HandleInfoRequest(packet); break;
            case GIncoming.PacketIntercept: HandlePacketIntercept(packet); break;
            case GIncoming.FlagsCheck: HandleFlagsCheck(packet); break;
            case GIncoming.ConnectionStart: HandleConnectionStart(packet); break;
            case GIncoming.ConnectionEnd: HandleConnectionEnd(packet); break;
            case GIncoming.Init: HandleInit(packet); break;
            default: break;
        };
    }

    private void HandleClick(Packet _) => OnActivated();

    private void HandleInfoRequest(Packet _)
    {
        using Packet p = new((Direction.Out, (short)GOutgoing.Info), capacity: 256);

        p.Write(
            Options.Name, Options.Author,
            Options.Version, Options.Description,
            Options.ShowEventButton,
            !string.IsNullOrWhiteSpace(_currentConnectOpts.FileName),
            _currentConnectOpts.FileName ?? "",
            _currentConnectOpts.Cookie ?? "",
            Options.ShowLeaveButton, Options.ShowDeleteButton
        );

        SendInternal(p);
    }

    /* int length
     * byte[length] intercepted packet info, a tab delimited "string" with 4 sections:
     *   1: whether the packet is blocked, either '0' or '1'
     *   2: an integer represented as a string, the index/sequence number of the packet
     *   3: the destination of the intercepted packet, either "TOCLIENT" or "TOSERVER"
     *   4: the packet data, which consists of:
     *     1: whether the packet has been modified by another extension, either '0' or '1'
     *     2: int length (of the 2-byte header + data)
     *     ^ -- note: not present on Shockwave sessions
     *     3: short header
     *     4: byte[] data
     * int: an integer specifying the packet format
     *   0 - Eva Wire (Flash, Unity)
     *   1 - Wedgie Incoming (Shockwave)
     *   2 - Wedgie Outgoing (Shockwave)
     */
    private (IPacket packet, int sequence, bool isBlocked, bool isModified) ParseInterceptArgs(Packet packet)
    {
        ReadOnlySpan<byte> packetBuffer = packet.Buffer.Span;

        int length = BinaryPrimitives.ReadInt32BigEndian(packetBuffer[0..4]);
        ReadOnlySpan<byte> data = packetBuffer[4..(4+length)];

        Span<int> tabs = stackalloc int[3];
        int current = 0;
        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] == Tab)
            {
                tabs[current++] = i;
                if (current == tabs.Length)
                    break;
            }
        }

        if (current != tabs.Length)
            throw new InvalidOperationException("Invalid packet intercept data (insufficient delimiter bytes).");

        bool isBlocked = data[0] == '1';
        int sequence = int.Parse(data[(tabs[0]+1)..tabs[1]]);
        bool isOutgoing = data[tabs[1] + 3] == 'S';
        bool isModified = data[tabs[2] + 1] == '1';

        Direction direction = isOutgoing ? Direction.Out : Direction.In;

        ReadOnlySpan<byte> packetSpan = data[(tabs[2] + 2)..];

        int dataOffset;
        short headerValue;

        if (Session.Client.Type == ClientType.Shockwave)
        {
            dataOffset = 2;
            headerValue = B64.Decode(packetSpan[0..2]);
        }
        else
        {
            dataOffset = 6;
            headerValue = BinaryPrimitives.ReadInt16BigEndian(packetSpan[4..6]);
        }

        Header header = new(Session.Client.Type, direction, headerValue);

        return (new Packet(header, packetSpan[dataOffset..]), sequence, isBlocked, isModified);
    }

    private void HandlePacketIntercept(Packet packet)
    {
        var (interceptedPacket, sequence, isBlocked, isModified) = ParseInterceptArgs(packet);
        using IPacket originalPacket = interceptedPacket;

        try
        {
            Intercept intercept = new(this, ref interceptedPacket, ref isBlocked) { Sequence = sequence };

            Header unmodifiedHeader = intercept.Packet.Header;
            int unmodifiedLength = intercept.Packet.Length;
            uint checksum = Crc32.HashToUInt32(intercept.Packet.Buffer.Span);

            OnIntercepted(intercept);
            Dispatcher.Dispatch(intercept);

            if (intercept.Packet.Header.Client != Session.Client.Type)
                throw new InvalidOperationException($"Invalid client {packet.Header.Client} on header, must be same as session: {Session.Client.Type}.");

            isModified =
                intercept.Packet.Header != unmodifiedHeader ||
                intercept.Packet.Length != unmodifiedLength ||
                checksum != Crc32.HashToUInt32(intercept.Packet.Buffer.Span);

            string sequenceStr = intercept.Sequence.ToString();
            int sequenceBytes = Encoding.ASCII.GetByteCount(sequenceStr);

            using Packet p = new(
                (Direction.Out, (short)GOutgoing.ManipulatedPacket),
                capacity: 23 + sequenceBytes + packet.Length
            );

            // packet length placeholder
            p.Write(-1);

            p.Write((byte)(intercept.IsBlocked ? '1' : '0'));
            p.Write(Tab);

            Encoding.ASCII.GetBytes(sequenceStr, p.Allocate(sequenceBytes));
            p.Write(Tab);

            p.WriteSpan(intercept.Direction == Direction.In ? "TOCLIENT"u8 : "TOSERVER"u8);
            p.Write(Tab);

            p.Write((byte)(isModified ? '1' : '0'));
            if (Session.Client.Type == ClientType.Shockwave)
            {
                B64.Encode(p.Allocate(2), intercept.Packet.Header.Value);
            }
            else
            {
                p.Write(2 + intercept.Packet.Length);
                p.Write(intercept.Packet.Header.Value);
            }

            p.WriteSpan(intercept.Packet.Buffer.Span);
            p.WriteAt(0, p.Length - 4);

            p.Write(ToPacketFormat(packet.Header));

            SendInternal(p);
        }
        finally
        {
            interceptedPacket.Dispose();
        }
    }

    private static void HandleFlagsCheck(Packet _) { }

    private void HandleConnectionStart(Packet packet)
    {
        var (host, port, clientVersion, clientIdentifier, clientTypeStr)
            = packet.Read<string, int, string, string, string>();

        ClientType clientType = clientTypeStr switch
        {
            "UNITY" => ClientType.Unity,
            "FLASH" => ClientType.Flash,
            "SHOCKWAVE" => ClientType.Shockwave,
            _ => ClientType.None,
        };

        Hotel hotel = Hotel.FromGameHost(host);

        int n = packet.Read<int>();
        List<ClientMessage> messages = new(n);
        for (int i = 0; i < n; i++)
        {
            var (id, _, name, _, isOutgoing, _)
                = packet.Read<int, string, string, string, bool, string>();
            messages.Add(new(clientType, isOutgoing ? Direction.Out : Direction.In, (short)id, name));
        }

        Messages.LoadMessages(messages);

        Session = new(hotel, new Client(clientType, clientIdentifier, clientVersion));
        IsConnected = true;

        OnConnected(new GameConnectedArgs
        {
            Host = host,
            Port = port,
            Session = Session,
            Messages = messages,
        });

        if (this is IMessageHandler handler)
            handler.Attach(this);
    }

    private void HandleConnectionEnd(Packet _)
    {
        try
        {
            IsConnected = false;
            Dispatcher.Reset();
            OnDisconnected();
        }
        finally
        {
            Session = Session.None;
        }
    }

    private void HandleInit(Packet packet)
    {
        bool? isGameConnected = (packet.Position < packet.Length) ? packet.Read<bool>() : null;

        OnInitialized(new InitializedArgs(isGameConnected));
    }

    /// <summary>
    /// Sends the specified packet to G-Earth.
    /// </summary>
    protected void SendInternal(Packet packet)
    {
        NetworkStream? ns = _ns;
        if (ns is null) return;

        _sendSemaphore.Wait();
        try
        {
            Span<byte> head = stackalloc byte[6];
            BinaryPrimitives.WriteInt32BigEndian(head[0..4], 2 + packet.Length);
            BinaryPrimitives.WriteInt16BigEndian(head[4..6], packet.Header.Value);
            ns.Write(head);
            ns.Write(packet.Buffer.Span);
        }
        finally { _sendSemaphore.Release(); }
    }
}
