﻿using System;
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

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Xabbo.Messages;
using Xabbo.Extension;
using Xabbo.Interceptor;

namespace Xabbo.GEarth;

/// <summary>
/// A G-Earth extension protocol implementation.
/// </summary>
public partial class GEarthExtension : IRemoteExtension, IInterceptorContext, INotifyPropertyChanged
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

    private readonly ILogger Log;

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

    IInterceptor IInterceptorContext.Interceptor => this;

    /// <summary>
    /// Creates a new <see cref="GEarthExtension"/> with the specified <see cref="GEarthOptions"/>.
    /// </summary>
    /// <param name="options">The options to be used by this extension.</param>
    /// <param name="messages">The message manager to use.</param>
    /// <param name="loggerFactory">The logger factory to use.</param>
    public GEarthExtension(
        GEarthOptions? options = null,
        IMessageManager? messages = null,
        ILoggerFactory? loggerFactory = null)
    {
        Log = (ILogger?)loggerFactory?.CreateLogger<GEarthExtension>() ?? NullLogger.Instance;
        Messages = messages ?? new MessageManager("messages.ini");
        Dispatcher = new MessageDispatcher(this);

        options ??= GEarthOptions.Default;

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

    private async Task HandleInterceptorAsync(GEarthConnectOptions connectOpts, CancellationToken cancellationToken)
    {
        bool connected = false;
        try
        {
            Log.Debug("Connecting to G-Earth on {Host}:{Port}", connectOpts.Host, connectOpts.Port);

            _tcpClient = await ConnectAsync(connectOpts, cancellationToken);
            connected = true;

            Log.Info("Connected to G-Earth on {Host}:{Port}");

            Pipe pipe = new();
            await Task.WhenAll(
                FillPipeAsync(_ns = _tcpClient.GetStream(), pipe.Writer, cancellationToken),
                ProcessPipeAsync(pipe.Reader, cancellationToken)
            );
        }
        catch (Exception ex)
        {
            if (!connected)
                throw new Exception($"Failed to connected to G-Earth on {connectOpts.Host}:{connectOpts.Port}.");

            if (ex is not UnhandledInterceptException)
                Log.Critical(ex, "{Message}", args: [ex.Message]);

            throw;
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

        TcpClient client = new();
        await client.ConnectAsync(host, port, cancellationToken);
        Port = port;
        return client;
    }

    private static async Task FillPipeAsync(Stream stream, PipeWriter writer, CancellationToken cancellationToken)
    {
        const int minimumBufferSize = 4096;

        try
        {
            while (true)
            {
                Memory<byte> memory = writer.GetMemory(minimumBufferSize);

                int bytesRead = await stream.ReadAsync(memory, cancellationToken);
                if (bytesRead == 0) break;

                writer.Advance(bytesRead);

                FlushResult result = await writer.FlushAsync(cancellationToken);
                if (result.IsCompleted) break;
            }
        }
        catch (IOException) { }

        await writer.CompleteAsync();
    }

    private async Task ProcessPipeAsync(PipeReader reader, CancellationToken cancellationToken)
    {
        while (true)
        {
            ReadResult result = await reader.ReadAsync(cancellationToken);
            ReadOnlySequence<byte> buffer = result.Buffer;

            try
            {
                while (TryReadPacketData(ref buffer, out ReadOnlySequence<byte> data))
                {
                    using Packet packet = new(
                        (Direction.In, ParsePacketHeader(data)),
                        data.Slice(2, data.Length - 2)
                    );
                    HandlePacket(packet);
                }

                if (result.IsCompleted) break;
            }
            catch
            {
                _ns?.Close();
                throw;
            }
            finally
            {
                reader.AdvanceTo(buffer.Start, buffer.End);
            }
        }

        await reader.CompleteAsync();
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

    private static bool TryReadPacketData(ref ReadOnlySequence<byte> buffer, out ReadOnlySequence<byte> data)
    {
        if (buffer.Length < 4)
        {
            data = default;
            return false;
        }

        int packetLength = ParsePacketLength(buffer);
        if (buffer.Length < (4 + packetLength))
        {
            data = default;
            return false;
        }

        data = buffer.Slice(4, packetLength);
        buffer = buffer.Slice(4 + packetLength);
        return true;
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
            default:
                Log.Warn("Unhandled packet received from G-Earth with header {Header}.", args: [packet.Header.Value]);
                break;
        };
    }

    private void HandleClick(Packet _) => OnActivated();

    private void HandleInfoRequest(Packet _)
    {
        Log.Debug("Extension information requested by G-Earth.");

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
            throw new FormatException("Invalid packet intercept data (insufficient delimiter bytes).");

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

        return (
            new Packet(header, packetSpan[dataOffset..]) { Context = this },
            sequence, isBlocked, isModified
        );
    }

    private void HandlePacketIntercept(Packet rawPacketIntercept)
    {
        var (packet, sequence, isBlocked, isModified) = ParseInterceptArgs(rawPacketIntercept);
        using IPacket originalPacket = packet;

        try
        {
            Intercept intercept = new(this, ref packet, ref isBlocked) { Sequence = sequence };

            Header unmodifiedHeader = packet.Header;
            int unmodifiedLength = packet.Length;
            uint checksum = 0;
            if (!isModified)
                checksum = Crc32.HashToUInt32(packet.Buffer.Span);

            try
            {
                OnIntercepted(intercept);
                Dispatcher.Dispatch(intercept);
            }
            catch (UnhandledInterceptException ex)
            {
                string messageName = "?";
                if (Messages.TryGetNames(unmodifiedHeader, out MessageNames names))
                    messageName = names.GetName(unmodifiedHeader.Client) ?? "?";
                Log.Error(ex, "Unhandled exception in handler {Header} ({MessageName}): {Error}",
                    args: [unmodifiedHeader, messageName, ex.InnerException?.Message]);
                throw;
            }

            if (packet.Header.Client != Session.Client.Type)
                throw new InvalidOperationException($"Invalid client {packet.Header.Client} on header, must be same as session: {Session.Client.Type}.");

            isModified =
                isModified ||
                packet.Header != unmodifiedHeader ||
                packet.Length != unmodifiedLength ||
                checksum != Crc32.HashToUInt32(packet.Buffer.Span);

            string sequenceStr = intercept.Sequence.ToString();
            int sequenceBytes = Encoding.ASCII.GetByteCount(sequenceStr);

            using Packet response = new(
                (Direction.Out, (short)GOutgoing.ManipulatedPacket),
                capacity: 23 + sequenceBytes + packet.Length
            );

            // packet length placeholder
            response.Write(-1);

            response.Write((byte)(intercept.IsBlocked ? '1' : '0'));
            response.Write(Tab);

            Encoding.ASCII.GetBytes(sequenceStr, response.Allocate(sequenceBytes));
            response.Write(Tab);

            response.WriteSpan(intercept.Direction == Direction.In ? "TOCLIENT"u8 : "TOSERVER"u8);
            response.Write(Tab);

            response.Write((byte)(isModified ? '1' : '0'));
            if (Session.Client.Type == ClientType.Shockwave)
            {
                B64.Encode(response.Allocate(2), packet.Header.Value);
            }
            else
            {
                response.Write(2 + packet.Length);
                response.Write(packet.Header.Value);
            }

            response.WriteSpan(packet.Buffer.Span);
            response.WriteAt(0, response.Length - 4);

            response.Write(ToPacketFormat(packet.Header));

            SendInternal(response);
        }
        finally
        {
            packet.Dispose();
        }
    }

    private void HandleFlagsCheck(Packet _) => Log.Trace("Received flags check.");

    private void HandleConnectionStart(Packet packet)
    {
        var (host, port, clientVersion, clientIdentifier, clientTypeStr)
            = packet.Read<string, int, string, string, string>();

        ClientType clientType = clientTypeStr switch
        {
            "UNITY" => ClientType.Unity,
            "FLASH" => ClientType.Flash,
            "SHOCKWAVE" => ClientType.Shockwave,
            _ => throw new Exception($"Unknown client type received from G-Earth: '{clientTypeStr}'.")
        };

        Hotel hotel = Hotel.FromGameHost(host);
        if (hotel == Hotel.None)
            Log.Warn("Unknown hotel for game host '{Host}'.", args: [host]);

        int n = packet.Read<int>();
        List<ClientMessage> messages = new(n);
        for (int i = 0; i < n; i++)
        {
            var (id, _, name, _, isOutgoing, _)
                = packet.Read<int, string, string, string, bool, string>();
            messages.Add(new(clientType, isOutgoing ? Direction.Out : Direction.In, (short)id, name));
        }

        Log.Info("Game connection to {Host}:{Port} on {Client} ({ClientVersion}) established.",
            args: [host, port, clientType, clientVersion]);

        Messages.LoadMessages(messages);

        Log.Info("Loaded {Count} messages.", args: [messages.Count]);

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
        {
            Log.Trace("Attaching extension to dispatcher.");
            handler.Attach(this);
        }
    }

    private void HandleConnectionEnd(Packet _)
    {
        Log.Info("Game connection ended.");
        IsConnected = false;
        Dispatcher.Reset();
        Session = Session.None;
        OnDisconnected();
    }

    private void HandleInit(Packet packet)
    {
        bool? isGameConnected = (packet.Position < packet.Length) ? packet.Read<bool>() : null;

        Log.Info("Extension initialized by G-Earth. (game connected: {Connected})", args: [isGameConnected]);

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
