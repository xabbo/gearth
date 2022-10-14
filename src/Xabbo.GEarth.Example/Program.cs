using Xabbo.GEarth;
using Xabbo.GEarth.Example;

Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("> Running extension...\n");
Console.ResetColor();

await new ExampleExtension(GEarthOptions.FromArgs(args)).RunAsync();