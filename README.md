![Nuget (with prereleases)](https://img.shields.io/nuget/vpre/Xabbo.GEarth?style=for-the-badge) ![NuGet downloads](https://img.shields.io/nuget/dt/Xabbo.GEarth?style=for-the-badge)

# xabbo/gearth
A framework for creating [G-Earth](https://github.com/sirjonasxx/G-Earth) extensions.
See the [examples](https://github.com/xabbo/examples) repository for example extensions using WinForms and WPF.

### Building from source
Requires the [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0).

- Clone the repository & fetch submodules.
```
git clone https://github.com/xabbo/gearth xabbo/gearth
cd xabbo/gearth
git submodule update --init
git submodule foreach 'git checkout -b xabbo/gearth'
```
- Build with the .NET CLI.
```
dotnet build
```
