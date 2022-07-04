using Xabbo.Interceptor;
using Xabbo.Messages;
using Xabbo.GEarth;

var ext = new CustomExtension(GEarthOptions.Default
    .WithName("Xabbo.GEarth test")
    .WithAuthor("b7")
);

Console.WriteLine("Running extension...");
await ext.RunAsync();

class CustomExtension : GEarthExtension
{
    public CustomExtension(GEarthOptions options)
        : base(options)
    { }

    protected override void OnInterceptorConnected()
    {
        base.OnInterceptorConnected();

        Console.WriteLine($"Connected to G-Earth on port {Port}.");
    }

    protected override void OnInitialized(InterceptorInitializedEventArgs e)
    {
        base.OnInitialized(e);

        Console.WriteLine($"Extension initialized by G-Earth. (game connected = {e.IsGameConnected})");
    }

    protected override void OnConnected(GameConnectedEventArgs e)
    {
        base.OnConnected(e);

        Console.WriteLine("Game connection established.");
        Console.WriteLine($"*       Client type: {e.ClientType}");
        Console.WriteLine($"* Client identifier: {e.ClientIdentifier}");
        Console.WriteLine($"*    Client version: {e.ClientVersion}");
        Console.WriteLine($"*       Host / port: {e.Host}:{e.Port}");
        Console.WriteLine($"*     Message count: {e.Messages.Count}");
        Console.WriteLine();

        /*
         * Bind an intercept handler to the interceptor dispatcher.
         * This must be done once a connection to the game has been established
         * as message names (identifiers) need to be resolved to headers by the message manager.
         */
        this.Bind(new CommandHandler(this));
    }

    // Sending packets
    [InterceptOut(nameof(Outgoing.Move))]
    protected async void OnMove(InterceptArgs e)
    {
        // Tuple deconstruction from packet
        var (x, y) = e.Packet.Read<int, int>();

        // Sending incoming packets to client
        await this.SendAsync(In.Whisper, -1, $"moving to {x}, {y}", 0, 0, 0, 0);
    }

    // Modifying packets
    // Change incoming shout messages to uppercase
    [InterceptIn(nameof(Incoming.Shout))]
    protected void OnUserShout(InterceptArgs e)
    {
        // Skip user index int
        e.Packet.Skip(4);
        string message = e.Packet.ReadString();
        // Replace a string from the 4th byte
        e.Packet.ReplaceString(message.ToUpper(), 4);
    }
}

// An intercept handler that can be bound to the interceptor's dispatcher
class CommandHandler : IInterceptHandler
{
    private readonly IInterceptor _interceptor;

    protected Outgoing Out => _interceptor.Messages.Out;
    protected Incoming In => _interceptor.Messages.In;

    public CommandHandler(IInterceptor interceptor)
    {
        _interceptor = interceptor;
    }

    private async Task HandleCommand(string cmd, string[] args)
    {
        cmd = cmd.ToLower();

        switch (cmd)
        {
            case "wave":
                {
                    // Access a header by its Flash message name "AvatarExpression".
                    // Maps to the Outgoing property Out.Expression, which is the Unity message name.
                    // This mapping is defined in the messages.ini file: Expression = 94; AvatarExpression
                    // This file can be included with the extension, or it will be downloaded from the
                    // b7c/Xabbo.Messages github repo by the message manager upon initialization if it does not exist.
                    await _interceptor.SendAsync(Out["AvatarExpression"], 1);
                }
                break;
            case "credits":
                {
                    // Send a request and receive a response asynchronously
                    await _interceptor.SendAsync(In.Chat, -1, "Requesting wallet balance...", 0, 0, 0, 0);
                    await _interceptor.SendAsync(Out.GetCredits);
                    using var p = await _interceptor.ReceiveAsync(In.WalletBalance, timeout: 10000, true);
                    await _interceptor.SendAsync(In.Chat, -1, $"You have {p.ReadString()} credits.", 0, 0, 0, 0);
                }
                break;
        }
    }

    [InterceptOut(nameof(Outgoing.Chat))]
    protected async void OnChat(InterceptArgs e)
    {
        try
        {
            string message = e.Packet.ReadString();
            Console.WriteLine($"Outgoing chat: \"{message}\"");

            if (message.StartsWith('/'))
            {
                e.Block(); // Blocking packets

                string[] args = message[1..].Split();
                await HandleCommand(args[0], args[1..]);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
        }
    }
}