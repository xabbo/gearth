using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

using Scriban;

namespace Xabbo.GEarth.Internal.Generator;

[Generator]
public class SourceGenerator : ISourceGenerator
{
    const int MaxParams = 16;

    private static Stream GetResourceStream(string resourceName)
    {
        resourceName = "Xabbo.GEarth.Internal.Generator." + resourceName;
        return Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)
            ?? throw new Exception($"Failed to load resource: '{resourceName}'.");
    }

    private static string GetTemplate(string resourceName)
    {
        using Stream stream = GetResourceStream(resourceName);
        using StreamReader sr = new(stream);
        return sr.ReadToEnd();
    }

    private static SourceText RenderTemplate(string resourceName, object model)
    {
        var template = Template.Parse(GetTemplate(resourceName));
        if (template.HasErrors)
        {
            foreach (var msg in template.Messages)
                Console.WriteLine(msg.Message);
            throw new Exception($"Error in {resourceName}: {template.Messages}");
        }
        string renderedTemplate = template.Render(model);
        return SourceText.From(renderedTemplate, Encoding.UTF8);
    }

    public void Initialize(GeneratorInitializationContext context)
    {
#if DEBUG
        if (!Debugger.IsAttached)
        {
            // For debugging the source generator
            // Debugger.Launch();
        }
#endif
    }

    public void Execute(GeneratorExecutionContext context)
    {
        context.AddSource("GEarthExtension.g.cs", RenderTemplate("GEarthExtension.sbncs", new { MaxParams }));
    }
}
