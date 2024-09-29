using System.Reflection;

namespace Xabbo.GEarth;

/// <summary>
/// Specifies the options to be used by <see cref="GEarthExtension"/>.
/// </summary>
public sealed record GEarthOptions
{
    public GEarthOptions()
    {
        if (Assembly.GetEntryAssembly() is { } assembly)
        {
            string? version = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion;

            if (assembly.GetName() is { } assemblyName)
            {
                if (assemblyName.Name is string name)
                    Name = name;
                version ??= assemblyName.Version?.ToString(3);
            }

            if (version is not null)
                Version = version;
        }
    }

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
    public string Version { get; init; } = "(no version)";

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
}
