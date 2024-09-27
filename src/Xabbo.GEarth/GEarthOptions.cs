using System.Reflection;

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
        .WithAssemblyVersion(DefaultVersionFieldCount);

    /// <summary>
    /// The name of the extension.
    /// </summary>
    public string Name { get; init; } = "(no name)";

    /// <summary>
    /// The description of the extension.
    /// </summary>
    public string Description { get; init; } = "(no description)";

    /// <summary>
    /// The author of the extension.
    /// </summary>
    public string Author { get; init; } = "(no author)";

    /// <summary>
    /// The version of the extension.
    /// </summary>
    public string Version { get; init; } = "alpha";

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
    /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Name"/>
    /// changed to the name of the current assembly.
    /// </summary>
    public GEarthOptions WithAssemblyName() => this with
    {
        Name = Assembly.GetEntryAssembly()?.GetName().Name ?? "unknown",
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
        Version = Assembly.GetEntryAssembly()?
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion ?? "unknown"
    };
}
