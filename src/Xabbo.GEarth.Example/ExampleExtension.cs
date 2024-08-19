using System.Runtime.CompilerServices;

using Xabbo.Connection;
using Xabbo.Extension;
using Xabbo.Messages;

namespace Xabbo.GEarth.Example;

// TODO:
// [Title("Example Extension")]
// [Description("A Xabbo.GEarth example extension")]
// [Author("b7")]
class ExampleExtension(ReadOnlySpan<string> args)
    : GEarthExtension(opts.WithArguments(args))
{
    private static readonly GEarthOptions opts = new() {
        Title = "xabbo/gearth",
        Description = "An example extension for xabbo/gearth",
        Author = "b7",
    };

    protected override void OnInitialized(InitializedArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"> Extension initialized by G-Earth. (game connected = {e.IsGameConnected})\n");
        Console.ResetColor();
    }

    protected override void OnActivated()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"> Extension clicked in G-Earth.\n");
        Console.ResetColor();
    }

    protected override void OnConnected(GameConnectedArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("> Game connection established.\n");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"        Client type: {e.Session.Client.Type}");
        Console.WriteLine($"  Client identifier: {e.Session.Client.Identifier}");
        Console.WriteLine($"     Client version: {e.Session.Client.Version}");
        Console.WriteLine($"              Hotel: {e.Session.Hotel.Name}");
        Console.WriteLine($"        Host / port: {e.Host}:{e.Port}");
        Console.WriteLine($"      Message count: {e.Messages.Count}");
        Console.WriteLine();
        Console.ResetColor();

        // Register intercepts here
        this.Intercept(Out.MoveAvatar, OnMove);
        this.Intercept([Out.Chat, Out.Shout, Out.Whisper], HandleOutgoingChat);
        this.Intercept([In.Chat, In.Shout, In.Whisper], HandleIncomingChat);
    }

    protected override void OnDisconnected()
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("> Game connection lost.\n");
        Console.ResetColor();
    }

    // Sending packets
    // TODO: source generation for intercept attributes.
    // [InterceptOut("Move")]
    protected void OnMove(Intercept e)
    {
        // Read x, y integers separately
        // int x = e.Packet.Read<int>();
        // int y = e.Packet.Read<int>();
        // or:
        // Read a tuple from the packet and deconstruct it
        var (x, y) = Session.Client.Type switch {
            ClientType.Shockwave => e.Packet.Read<short, short>(),
            _ => e.Packet.Read<int, int>(),
        };

        // Sending incoming chat packet to client
        this.Send(In.Chat, 0, $"moving to {x}, {y}", 0, 0, 0, 0);
    }

    // Modifying packets
    // Changes incoming shout messages to uppercase,
    // and whisper messages to lowercase
    // [InterceptIn("Chat", "Shout", "Whisper")]
    protected void HandleIncomingChat(Intercept e)
    {
        // Skip over the entity index
        e.Packet.Read<int>();

        if (e.Is(In.Whisper))
        {
            // Modify a string from the current position in the packet
            e.Packet.Modify<string>(msg => msg.ToLower());
        }
        else if (e.Is(In.Shout))
        {
            e.Packet.Modify<string>(msg => msg.ToUpper());
        }
    }

    // Intercept outgoing Chat, Shout and Whisper packets
    // [InterceptOut("Chat", "Shout", "Whisper")]
    protected void HandleOutgoingChat(Intercept e)
    {
        try
        {
            // Read the message from the packet
            string message = e.Packet.Read<string>();

            // Remove the recipient from the message if this is a whisper
            // TODO: Messages.Is(e.Packet.Header, Out.Whisper)
            if (e.Packet.Header == Messages.Resolve(Out.Whisper))
            {
                int index = message.IndexOf(' ');
                if (index > 0)
                    message = message[(index + 1)..];
            }

            message = message.Trim();
            if (message.StartsWith('/'))
            {
                // Block the message if it starts with a forward slash and process it as a command
                e.Block();
                HandleCommand(message[1..]);
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"> Error: ${ex.Message}");
        }
    }

    private void HandleCommand(string command)
    {
        command = command.ToLower();

        switch (command)
        {
            case "wave":
                {
                    if (Session.Client.Type == ClientType.Shockwave)
                    {
                        // Shockwave has a packet just for wave
                        this.Send(ShockwaveOut.Wave);
                    }
                    else
                    {
                        // Modern clients have avatar expression
                        // with an action type (1 = wave)
                        this.Send(Out.AvatarExpression, 1);
                    }
                }
                break;
            case "credits":
                {
                    // Send a request and receive a response asynchronously
                    Task.Run(async () => {
                        try
                        {
                            this.Send(In.Chat, 0, "Requesting wallet balance...", 0, 0, 0, 0);
                            this.Send(Out.GetCreditsInfo);
                            using var p = await this.ReceiveAsync(In.CreditBalance, timeout: 10000, true);
                            this.Send(In.Chat, 0, $"You have {p.Read<string>()} credits.", 0, 0, 0, 0);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex);
                        }
                    });
                }
                break;
        }
    }
}

// TODO: create Xabbo.Messages package that exports all client identifiers
internal static class In
{
    private static Identifier _([CallerMemberName] string? name = null)
        => new(ClientType.Flash, Direction.In, name ?? "");
    public static readonly Identifier CreditBalance = _();
    public static readonly Identifier Chat = _();
    public static readonly Identifier Shout = _();
    public static readonly Identifier Whisper = _();
}

internal static class Out
{
    private static Identifier _([CallerMemberName] string? name = null)
        => new(ClientType.Flash, Direction.Out, name ?? "");
    public static readonly Identifier MoveAvatar = _();
    public static readonly Identifier AvatarExpression = _();
    public static readonly Identifier Chat = _();
    public static readonly Identifier Shout = _();
    public static readonly Identifier Whisper = _();
    public static readonly Identifier GetCreditsInfo = _();
}

internal static class ShockwaveOut
{
    private static Identifier _([CallerMemberName] string? name = null)
        => new(ClientType.Shockwave, Direction.Out, name ?? "");
    public static readonly Identifier Wave = _();
}
