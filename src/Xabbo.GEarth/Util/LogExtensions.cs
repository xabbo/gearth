using System;
using System.Runtime.CompilerServices;

using Microsoft.Extensions.Logging;

namespace Xabbo.GEarth;

internal static class LogExtensions
{
    #pragma warning disable CA2254
    public static void Trace(this ILogger? logger, string format,
        [CallerMemberName] string? caller = null,
        params object?[] args)
    {
        logger?.LogTrace($"[{caller}] {format}", args);
    }

    public static void Debug(this ILogger? logger, string format,
        [CallerMemberName] string? caller = null,
        params object?[] args)
    {
        logger?.LogDebug($"[{caller}] {format}", args);
    }

    public static void Info(this ILogger? logger, string format,
        [CallerMemberName] string? caller = null,
        params object?[] args)
    {
        logger?.LogInformation($"[{caller}] {format}", args);
    }

    public static void Warn(this ILogger? logger, string format,
        [CallerMemberName] string? caller = null,
        params object?[] args)
    {
        logger?.LogWarning($"[{caller}] {format}", args);
    }

    public static void Error(this ILogger? logger, string format,
        [CallerMemberName] string? caller = null,
        params object?[] args)
    {
        logger?.LogError($"[{caller}] {format}", args);
    }

    public static void Error(this ILogger? logger, Exception? ex, string format,
        [CallerMemberName] string? caller = null,
        params object?[] args)
    {
        logger?.LogError(ex, $"[{caller}] {format}", args);
    }

    public static void Critical(this ILogger? logger, string format,
        [CallerMemberName] string? caller = null,
        params object?[] args)
    {
        logger?.LogCritical($"[{caller}] {format}", args);
    }

    public static void Critical(this ILogger? logger, Exception? ex, string format,
        [CallerMemberName] string? caller = null,
        params object?[] args)
    {
        logger?.LogCritical(ex, $"[{caller}] {format}", args);
    }
    #pragma warning restore CA2254
}
