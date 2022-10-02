using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

using Microsoft.Extensions.Configuration;

namespace Xabbo.GEarth
{
    /// <summary>
    /// Specifies the options to be used by <see cref="GEarthExtension"/>.
    /// </summary>
    public class GEarthOptions
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
        /// The title of the extension.
        /// </summary>
        public string Title { get; init; }

        /// <summary>
        /// The description of the extension.
        /// </summary>
        public string Description { get; init; }

        /// <summary>
        /// The author of the extension.
        /// </summary>
        public string Author { get; init; }

        /// <summary>
        /// The version of the extension.
        /// </summary>
        public string Version { get; init; }

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
        public string FileName { get; init; }

        /// <summary>
        /// The cookie to be used for authentication.
        /// </summary>
        public string Cookie { get; init; }

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
        /// Creates a new <see cref="GEarthOptions"/> instance.
        /// </summary>
        public GEarthOptions()
        {
            Title =
            Description =
            Author =
            Version =
            FileName =
            Cookie = string.Empty;
        }

        /// <summary>
        /// Creates a copy of the specified <see cref="GEarthOptions"/>.
        /// </summary>
        public GEarthOptions(GEarthOptions options)
        {
            Title = options.Title;
            Description = options.Description;
            Author = options.Author;
            Version = options.Version;

            ShowEventButton = options.ShowEventButton;
            ShowLeaveButton = options.ShowLeaveButton;
            ShowDeleteButton = options.ShowDeleteButton;

            FileName = options.FileName;
            Cookie = options.Cookie;

            Port = options.Port;
        }

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Title"/> changed.
        /// </summary>
        public GEarthOptions WithTitle(string title) => new(this) { Title = title };
        
        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Title"/>
        /// changed to the name of the current assembly.
        /// </summary>
        public GEarthOptions WithAssemblyName()
        {
            return new(this)
            {
                Title = Assembly.GetEntryAssembly()?
                    .GetName().Name
                    ?? "unknown"
            };
        }

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Description"/> changed.
        /// </summary>
        public GEarthOptions WithDescription(string description) => new(this) { Description = description };

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Author"/> changed.
        /// </summary>
        public GEarthOptions WithAuthor(string author) => new(this) { Author = author };

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Version"/> changed.
        /// </summary>
        public GEarthOptions WithVersion(string version) => new(this) { Version = version };

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Version"/>
        /// changed to the version of the current assembly.
        /// </summary>
        /// <param name="fieldCount">The number of fields to include in the version.</param>
        public GEarthOptions WithAssemblyVersion(int fieldCount = 3)
        {
            return new(this)
            {
                Version = Assembly.GetEntryAssembly()?
                    .GetName().Version?
                    .ToString(fieldCount)
                    ?? "unknown"
            };
        }

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Version"/>
        /// changed to the informational version of the current assembly.
        /// </summary>
        public GEarthOptions WithInformationalVersion()
        {
            return new(this)
            {
                Version = Assembly.GetEntryAssembly()?
                    .GetCustomAttributes<AssemblyInformationalVersionAttribute>()
                    .FirstOrDefault()?
                    .InformationalVersion
                    ?? "unknown"
            };
        }

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with <see cref="ShowEventButton"/> changed.
        /// </summary>
        public GEarthOptions WithShowEventButton(bool showEventButton) => new(this) { ShowEventButton = showEventButton };

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with <see cref="ShowLeaveButton"/> changed.
        /// </summary>
        public GEarthOptions WithShowLeaveButton(bool showLeaveButton) => new(this) { ShowLeaveButton = showLeaveButton };

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with <see cref="ShowDeleteButton"/> changed.
        /// </summary>
        public GEarthOptions WithShowDeleteButton(bool showDeleteButton) => new(this) { ShowDeleteButton = showDeleteButton };

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="FileName"/> changed.
        /// </summary>
        public GEarthOptions WithFilePath(string filePath) => new(this) { FileName = filePath };
        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Cookie"/> changed.
        /// </summary>
        public GEarthOptions WithCookie(string cookie) => new(this) { Cookie = cookie };

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the <see cref="Port"/> changed.
        /// </summary>
        public GEarthOptions WithPort(int port) => new(this) { Port = port };

        /// <summary>
        /// Creates a new <see cref="GEarthOptions"/> with the specified arguments applied.
        /// </summary>
        public GEarthOptions WithArguments(IList<string> args)
        {
            int port = Port;
            string cookie = Cookie;
            string file = FileName;

            for (int i = 0; i < args.Count - 1; i++)
            {
                switch (args[i])
                {
                    case "-c":
                        cookie = args[++i];
                        break;
                    case "-f":
                        file = args[++i];
                        break;
                    case "-p":
                        string portArg = args[++i];
                        if (!int.TryParse(portArg, out port))
                            throw new FormatException($"Invalid port argument specified: '{portArg}'.");
                        break;
                    
                }
            }

            return new GEarthOptions(this)
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

            return new GEarthOptions(this)
            {
                Port = port,
                Cookie = cookie,
                FileName = file
            };
        }
    }
}
