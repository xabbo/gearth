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
using Xabbo.Extension;

namespace Xabbo.GEarth;

/// <summary>
/// An <see cref="IRemoteExtension"/> implementation for G-Earth.
/// </summary>
public class GEarthExtension : IRemoteExtension, INotifyPropertyChanged
{
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

    public event PropertyChangedEventHandler? PropertyChanged;

    private readonly SemaphoreSlim _sendSemaphore = new(1, 1);
    private readonly Memory<byte> _buffer = new byte[6];

    private TcpClient? _tcpClient;
    private NetworkStream? _ns;

    private CancellationTokenSource? _cancellation;

    private CancellationTokenSource _ctsDisconnect;

    public CancellationToken DisconnectToken => _ctsDisconnect.Token;

    #region - Events -
    public event EventHandler<InitializedArgs>? Initialized;
    protected virtual void OnInitialized(InitializedArgs e) => Initialized?.Invoke(this, e);

    public event EventHandler<GameConnectedArgs>? Connected;
    protected virtual void OnConnected(GameConnectedArgs e) => Connected?.Invoke(this, e);

    public event EventHandler? Disconnected;
    protected virtual void OnDisconnected()
    {
        _ctsDisconnect.Cancel();
        _ctsDisconnect = new CancellationTokenSource();

        Disconnected?.Invoke(this, EventArgs.Empty);
    }

    public event EventHandler<Intercept>? Intercepted;
    protected virtual void OnIntercepted(Intercept e) => Intercepted?.Invoke(this, e);

    /// <summary>
    /// Invoked when the extension is selected in G-Earth's user interface.
    /// </summary>
    public event EventHandler? Activated;
    protected virtual void OnActivated() => Activated?.Invoke(this, EventArgs.Empty);
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

    public void Send(IReadOnlyPacket packet) => ForwardPacket(packet);

    /// <summary>
    /// Creates a new <see cref="GEarthExtension"/> using the specified <see cref="IMessageManager"/> and <see cref="GEarthOptions"/>.
    /// </summary>
    /// <param name="messages">The message manager to be used by this extension.</param>
    /// <param name="options">The options to be used by this extension.</param>
    public GEarthExtension(IMessageManager messages, GEarthOptions options)
    {
        _ctsDisconnect = new CancellationTokenSource();

        Messages = messages;
        Options = options;

        Dispatcher = new MessageDispatcher(messages);
    }

    /// <summary>
    /// Creates a new <see cref="GEarthExtension"/> with the specified <see cref="GEarthOptions"/>.
    /// Uses a <see cref="MessageManager"/> which loads a file named <c>messages.ini</c>.
    /// </summary>
    /// <param name="options">The options to be used by this extension.</param>
    public GEarthExtension(GEarthOptions options)
        : this(new MessageManager("messages.ini"), options)
    { }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        if (IsRunning)
            throw new InvalidOperationException("The interceptor service is already running.");

        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

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

            Dispatcher.Reset();

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
        Exception? error = null;

        try
        {
            _tcpClient = await ConnectAsync(cancellationToken);

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

    private async Task<TcpClient> ConnectAsync(CancellationToken cancellationToken)
    {
        try
        {
            TcpClient client = new();
            await client.ConnectAsync(IPAddress.Loopback, Options.Port, cancellationToken);
            Port = Options.Port;
            return client;
        }
        catch
        {
            throw new Exception($"Failed to connect to G-Earth on port {Options.Port}.");
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

    private void HandlePacket(IReadOnlyPacket packet)
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

    private void HandleClick(IReadOnlyPacket _)
    {
        OnActivated();
    }

    private void HandleInfoRequest(IReadOnlyPacket _)
    {
        using Packet p = new(
            (Direction.Out, (short)GOutgoing.Info),
            capacity:
                16
                + Options.Title.Length
                + Options.Author.Length
                + Options.Version.Length
                + Options.Description.Length
                + Options.FileName.Length
                + Options.Cookie.Length
        );

        p.Write(
            Options.Title, Options.Author,
            Options.Version, Options.Description,
            Options.ShowEventButton,
            Options.IsInstalledExtension,
            Options.FileName, Options.Cookie,
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
     *     3: short header
     *     4: byte[] data
     *     5: an integer specifying the packet format
     *       0 - Eva Wire (Flash, Unity)
     *       1 - Wedgie Incoming (Shockwave)
     *       2 - Wedgie Outgoing (Shockwave)
     */
    private Intercept ParseInterceptArgs(IReadOnlyPacket packet)
    {
        ReadOnlySpan<byte> packetBuffer = packet.Buffer;

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
        short headerValue = BinaryPrimitives.ReadInt16BigEndian(packetSpan[4..6]);

        Header header = new(Session.Client.Type, direction, headerValue);

        return new Intercept(this, new Packet(header, packetSpan[6..])) { Sequence = sequence };
    }

    private void HandlePacketIntercept(IReadOnlyPacket packet)
    {
        using Intercept intercept = ParseInterceptArgs(packet);

        OnIntercepted(intercept);

        Dispatcher.Dispatch(intercept);

        string stepString = intercept.Sequence.ToString();
        int stepByteCount = Encoding.ASCII.GetByteCount(stepString);

        using Packet p = new((Direction.Out, (short)GOutgoing.ManipulatedPacket), capacity: 23 + stepByteCount + packet.Length);

        // length placeholder
        p.Write(-1);

        // is blocked
        p.Write((byte)(intercept.IsBlocked ? '1' : '0'));

        p.Write(Tab);

        // packet sequence number as a string
        Encoding.ASCII.GetBytes(stepString, p.Allocate(stepByteCount));
        p.Write(Tab);

        // packet destination
        p.Write(intercept.Direction == Direction.In ? "TOSERVER"u8 : "TOCLIENT"u8);

        p.Write(Tab);

        // is modified
        p.Write((byte)(intercept.IsModified ? '1' : '0'));
        // header + packet length
        p.Write(2 + intercept.Packet.Length);
        // packet header
        p.Write(intercept.Packet.Header.Value);
        // packet data
        p.Write(intercept.Packet.Buffer);

        p.Write(p.Length - 4, 0);

        SendInternal(p);
    }

    private static void HandleFlagsCheck(IReadOnlyPacket _) { }

    private void HandleConnectionStart(IReadOnlyPacket packet)
    {
        var (host, port, clientVersion, clientIdentifier, clientType)
            = packet.Read<string, int, string, string, string>();

        Clients client = clientType switch
        {
            "UNITY" => Clients.Unity,
            "FLASH" => Clients.Flash,
            "SHOCKWAVE" => Clients.Shockwave,
            _ => Clients.None,
        };

        Hotel hotel = Hotel.FromGameHost(host);

        int n = packet.Read<int>();
        List<ClientMessage> messages = new(n);
        for (int i = 0; i < n; i++)
        {
            var (id, _, name, _, isOutgoing, _)
                = packet.Read<int, string, string, string, bool, string>();

            messages.Add(new(client, isOutgoing ? Direction.Out : Direction.In, (short)id, name));
        }

        Messages.LoadMessages(messages);

        if (this is IMessageHandler handler)
            handler.Attach(this);

        Session = new(hotel, new Client(client, clientIdentifier, clientVersion));
        IsConnected = true;

        OnConnected(new GameConnectedArgs
        {
            Host = host,
            Port = port,
            Session = Session,
            Messages = messages,
        });
    }

    private void HandleConnectionEnd(IReadOnlyPacket _)
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

    private void HandleInit(IReadOnlyPacket packet)
    {
        bool? isGameConnected = packet.Available > 0 ? packet.Read<bool>() : null;

        Initialized?.Invoke(this, new InitializedArgs(isGameConnected));
    }

    /// <summary>
    /// Instructs G-Earth to forward the specified packet to the client or server.
    /// </summary>
    private void ForwardPacket(IReadOnlyPacket packet)
    {
        if (packet.Header.Direction != Direction.In &&
            packet.Header.Direction != Direction.Out)
        {
            throw new InvalidOperationException("Invalid packet destination.");
        }

        using var p = new Packet((Direction.Out, (short)GOutgoing.SendMessage), capacity: 11 + packet.Length);
        p.Write((byte)(packet.Header.Direction == Direction.Out ? 1 : 0));
        p.Write(6 + packet.Length); // length of (packet length + header + data)
        p.Write(2 + packet.Length); // length of (header + data)
        p.Write(packet.Header.Value);
        p.Write(packet.Buffer);
        SendInternal(p);
    }

    /// <summary>
    /// Sends the specified packet to G-Earth.
    /// </summary>
    protected void SendInternal(IReadOnlyPacket packet)
    {
        NetworkStream? ns = _ns;
        if (ns is null) return;

        _sendSemaphore.Wait();
        try
        {
            BinaryPrimitives.WriteInt32BigEndian(_buffer.Span[0..4], 2 + packet.Length);
            BinaryPrimitives.WriteInt16BigEndian(_buffer.Span[4..6], packet.Header.Value);
            ns.Write(_buffer.Span[0..6]);
            ns.Write(packet.Buffer);
        }
        finally { _sendSemaphore.Release(); }
    }
}
