using System;

namespace Xabbo.GEarth
{
    public class GEarthOptions
    {
        public string Title { get; init; }
        public string Author { get; init; }
        public string Version { get; init; }
        public string Description { get; init; }
        public bool FireEventButtonVisible { get; init; }
        public bool IsInstalledExtension { get; init; }
        public string FilePath { get; init; }
        public string Cookie { get; init; }
        public bool LeaveButtonVisible { get; init; }
        public bool DeleteButtonVisible { get; init; }

        public GEarthOptions()
        {
            Title =
            Author =
            Version =
            Description =
            FilePath =
            Cookie = string.Empty;
        }
    }
}
