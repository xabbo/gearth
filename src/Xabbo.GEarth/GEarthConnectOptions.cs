using System;

namespace Xabbo.GEarth;

public readonly record struct GEarthConnectOptions(
    string? Host = null,
    int? Port = null,
    string? FileName = null,
    string? Cookie = null
)
{
    public GEarthConnectOptions WithArgs(ReadOnlySpan<string> args, bool @override = false)
    {
        GEarthConnectOptions opts = this;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h":
                    if (++i >= args.Length) break;
                    if (opts.Host is null || @override)
                        opts = opts with { Host = args[i] };
                    break;
                case "-p":
                    if (++i >= args.Length) break;
                    if (!int.TryParse(args[i], out int port)) continue;
                    if (opts.Port is null || @override)
                        opts = opts with { Port = port };
                    break;
                case "-c":
                    if (++i >= args.Length) break;
                    if (opts.Cookie is null || @override)
                        opts = opts with { Cookie = args[i] };
                    break;
                case "-f":
                    if (++i >= args.Length) break;
                    if (opts.FileName is null || @override)
                        opts = opts with { FileName = args[i] };
                    break;
            }
        }
        return opts;
    }
}