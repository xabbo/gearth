using System;

namespace Xabbo.GEarth
{
    public class GEarthOptions
    {
        public string Title { get; init; }
        public string Description { get; init; }
        public string Author { get; init; }
        public string Version { get; init; }

        public bool ShowEventButton { get; init; }
        public bool ShowLeaveButton { get; init; }
        public bool ShowDeleteButton { get; init; }

        public string FilePath { get; init; }
        public string Cookie { get; init; }

        public bool IsInstalledExtension { get; init; }

        public GEarthOptions()
        {
            Title =
            Description =
            Author =
            Version =
            FilePath =
            Cookie = string.Empty;
        }
    }
}
