using System;
using System.Collections.Generic;
using System.Reflection;

using Microsoft.Extensions.Configuration;

using Xabbo.Extension;

namespace Xabbo.GEarth;

/// <summary>
/// Specifies the options to be used by <see cref="GEarthExtension"/>.
/// </summary>
public sealed record GEarthOptions
{
    /// <summary>
    /// The number of version fields to be included when converting the assembly version to a string for <see cref="Default"/>.
    /// </summary>
    public static int DefaultVersionFieldCount { get; set; } = 3;

    /// <summary>
    /// Gets the default options with the entry assembly's name and version.
    /// </summary>
    public static GEarthOptions Default => new GEarthOptions()
        .WithAssemblyName()
        .WithAssemblyVersion();

    /// <summary>
    /// Creates and returns a new default <see cref="GEarthOptions"/> instance with the specified command line arguments applied.
    /// </summary>
    public static GEarthOptions FromArgs(IList<string> args) => Default.WithArguments(args);

    /// <summary>
    /// The title of the extension.
    /// </summary>
    public string Title { get; init; } = string.Empty;

    /// <summary>
    /// The description of the extension.
    /// </summary>
    public string Description { get; init; } = string.Empty;

    /// <summary>
    /// The author of the extension.
    /// </summary>
    public string Author { get; init; } = string.Empty;

    /// <summary>
    /// The version of the extension.
    /// </summary>
    public string Version { get; init; } = string.Empty;

    /// <summary>
    /// Specifies whether to show the even (green play) button in G-Earth.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool ShowEventButton { get; init; } = true;

    /// <summary>
    /// Specifies whether to show the leave button in G-Earth.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool ShowLeaveButton { get; init; } = true;

    /// <summary>
    /// Specifies whether to show the delete button in G-Earth after the user disconnects from the extension.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool ShowDeleteButton { get; init; } = true;

    /// <summary>
    /// The file path of the extension.
    /// </summary>
    public string FileName { get; init; } = string.Empty;

    /// <summary>
    /// The cookie to be used for authentication.
    /// </summary>
    public string Cookie { get; init; } = string.Empty;

    /// <summary>
    /// Specifies whether the extension is installed.
    /// Returns <c>true</c> if <see cref="FileName"/> is a non-empty string.
    /// </summary>
    public bool IsInstalledExtension => !string.IsNullOrWhiteSpace(FileName);

    /// <summary>
    /// The port used to connect to G-Earth.
    /// Defaults to 9092.
    /// </summary>
    public int Port { get; init; } = 9092;

    /// <summary>
    /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Title"/>
    /// changed to the name of the current assembly.
    /// </summary>
    public GEarthOptions WithAssemblyName() => this with
    {
        Title = Assembly.GetEntryAssembly()?.GetName().Name ?? "unknown",
    };

    /// <summary>
    /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Version"/>
    /// changed to the version of the current assembly.
    /// </summary>
    /// <param name="fieldCount">The number of fields to include in the version.</param>
    public GEarthOptions WithAssemblyVersion(int fieldCount = 3) => this with
    {
        Version = Assembly.GetEntryAssembly()?.GetName().Version?.ToString(fieldCount) ?? "unknown"
    };

    /// <summary>
    /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Version"/>
    /// changed to the informational version of the current assembly.
    /// </summary>
    public GEarthOptions WithInformationalVersion() => this with
    {
        Version = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "unknown"
    };

    /// <summary>
    /// Creates a new <see cref="GEarthOptions"/> with the specified arguments applied.
    /// </summary>
    public GEarthOptions WithArguments(IList<string> args)
    {
        int port = Port;
        string cookie = Cookie;
        string file = FileName;

        for (int i = 0; i < args.Count; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "-c":
                case "--cookie":
                    if (++i >= args.Count)
                        throw new ArgumentException($"A value must be specified after {arg}.");
                    cookie = args[i];
                    break;
                case "-f":
                case "--filename":
                    if (++i >= args.Count)
                        throw new ArgumentException($"A value must be specified after {arg}.");
                    file = args[i];
                    break;
                case "-p":
                case "--port":
                    if (++i >= args.Count)
                        throw new ArgumentException($"A value must be specified after {arg}.");
                    string portString = args[i];
                    if (!int.TryParse(portString, out port) || port <= 0 || port > ushort.MaxValue)
                        throw new FormatException($"Invalid port specified: '{portString}'.");
                    break;
            }
        }

        return this with
        {
            Port = port,
            Cookie = cookie,
            FileName = file
        };
    }

    /// <summary>
    /// Creates a new <see cref="GEarthOptions"/> with the specified configuration applied.
    /// </summary>
    public GEarthOptions WithConfiguration(IConfiguration configuration)
    {
        int port = configuration.GetValue("Xabbo:Interceptor:Port", Port);
        string cookie = configuration.GetValue("Xabbo:Interceptor:Cookie", Cookie);
        string file = configuration.GetValue("Xabbo:Interceptor:File", FileName);

        return this with
        {
            Port = port,
            Cookie = cookie,
            FileName = file
        };
    }

    /// <summary>
    /// Applies the extension attributes attached to the specified type, if they exist,
    /// and returns the updated <see cref="GEarthOptions"/>.
    /// </summary>
    /// <param name="type">The type that derives from <see cref="GEarthExtension"/>.</param>
    internal GEarthOptions WithExtensionAttributes(Type type)
    {
        if (!type.IsAssignableTo(typeof(GEarthExtension)))
            throw new ArgumentException("The specified type must derive from GEarthExtension.");

        GEarthOptions options = this;
        if (type.GetCustomAttribute<TitleAttribute>() is TitleAttribute titleAttr)
            options = options with { Title = titleAttr.Title };
        if (type.GetCustomAttribute<AuthorAttribute>() is AuthorAttribute authorAttr)
            options = options with { Author = authorAttr.Author };
        if (type.GetCustomAttribute<DescriptionAttribute>() is DescriptionAttribute descriptionAttr)
            options = options with { Description = descriptionAttr.Description };
        if (type.GetCustomAttribute<VersionAttribute>() is VersionAttribute versionAttr)
            options = options with { Version = versionAttr.Version };

        return options;
    }
}
