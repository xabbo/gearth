using Xabbo.Interceptor;
using Xabbo.Messages;

namespace Xabbo.GEarth.Example;

// An intercept handler that can be bound to the interceptor's dispatcher
class CommandHandler : IMessageHandler
{
    private readonly IInterceptor _interceptor;

    protected Outgoing Out => _interceptor.Messages.Out;
    protected Incoming In => _interceptor.Messages.In;

    public CommandHandler(IInterceptor interceptor)
    {
        _interceptor = interceptor;
    }

    [InterceptOut(nameof(Outgoing.Chat))]
    protected void OnChat(InterceptArgs e)
    {
        try
        {
            string message = e.Packet.ReadString();
            Console.WriteLine($"Outgoing chat: \"{message}\"");

            if (message.StartsWith('/'))
            {
                e.Block(); // Blocking packets

                string[] args = message[1..].Split();
                // await HandleCommand(args[0], args[1..]);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
        }
    }
}
