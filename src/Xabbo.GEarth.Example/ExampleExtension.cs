using Xabbo.Extension;
using Xabbo.Messages;

namespace Xabbo.GEarth.Example;

[Title("Example Extension")]
[Description("A Xabbo.GEarth example extension")]
[Author("b7")]
class ExampleExtension : GEarthExtension
{
    public ExampleExtension(GEarthOptions options) : base(options) { }

    protected override void OnInterceptorConnected()
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"> Connected to G-Earth on port {Port}.\n");
        Console.ResetColor();
    }

    protected override void OnInitialized(ExtensionInitializedEventArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"> Extension initialized by G-Earth. (game connected = {e.IsGameConnected})\n");
        Console.ResetColor();
    }

    protected override void OnClicked()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"> Extension clicked in G-Earth.\n");
        Console.ResetColor();
    }

    protected override void OnConnected(GameConnectedEventArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("> Game connection established.\n");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"        Client type: {e.ClientType}");
        Console.WriteLine($"  Client identifier: {e.ClientIdentifier}");
        Console.WriteLine($"     Client version: {e.ClientVersion}");
        Console.WriteLine($"        Host / port: {e.Host}:{e.Port}");
        Console.WriteLine($"      Message count: {e.Messages.Count}");
        Console.WriteLine();
        Console.ResetColor();
    }

    protected override void OnDisconnected()
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("> Game connection lost.\n");
        Console.ResetColor();
    }

    // Sending packets
    [InterceptOut(nameof(Outgoing.Move))]
    protected void OnMove(InterceptArgs e)
    {
        // Read x, y integers separately
        // int x = e.Packet.ReadInt();
        // int y = e.Packet.ReadInt();
        // or:
        // Read a tuple from the packet and deconstruct it
        var (x, y) = e.Packet.Read<int, int>();

        // Sending incoming packets to client
        Send(In.Whisper, -1, $"moving to {x}, {y}", 0, 0, 0, 0);
    }

    // Modifying packets
    // Change incoming shout messages to uppercase
    [InterceptIn(nameof(Incoming.Shout))]
    protected void OnUserShout(InterceptArgs e)
    {
        // Read a string from byte index 4 in the packet
        // (skipping over user index int)
        string message = e.Packet.ReadString(4);
        // Replace a string from byte index 4 in the packet
        e.Packet.ReplaceString(message.ToUpper(), 4);
    }

    // Intercept outgoing Chat, Shout and Whisper packets
    [InterceptOut("Chat", "Shout", "Whisper")]
    protected async void OnChat(InterceptArgs e)
    {
        try
        {
            // Read the message from the packet
            string message = e.Packet.ReadString();

            // Remove the recipient from the message if this is a whisper
            if (e.Packet.Header == Out.Whisper)
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
                await HandleCommand(message[1..]);
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"> Error: ${ex.Message}");
        }
    }

    private async Task HandleCommand(string command)
    {
        command = command.ToLower();

        switch (command)
        {
            case "wave":
                {
                    // Access a header by its Flash message name "AvatarExpression".
                    // Maps to the Outgoing property Out.Expression, which is the Unity message name.
                    // This mapping is defined in the messages.ini file: Expression = 94; AvatarExpression
                    // This file can be included with the extension, or it will be downloaded from the
                    // b7c/Xabbo.Messages github repo by the message manager upon initialization if it does not exist.
                    await SendAsync(Out["AvatarExpression"], 1);
                }
                break;
            case "credits":
                {
                    // Send a request and receive a response asynchronously
                    await SendAsync(In.Chat, -1, "Requesting wallet balance...", 0, 0, 0, 0);
                    await SendAsync(Out.GetCredits);
                    using var p = await ReceiveAsync(In.WalletBalance, timeout: 10000, true);
                    await SendAsync(In.Chat, -1, $"You have {p.ReadString()} credits.", 0, 0, 0, 0);
                }
                break;
        }
    }
}
