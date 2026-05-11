/*======================================================================
 *  COPYRIGHT (c) 2026 | TEAM: COUNTER STRIKE BLEACH SQUID GAME 2
 *  Элитный исходный код. Все права защищены. Авторы — легенды CS2:
 *
 *  ЛЫСЕНКО АНДРЕЙ — IGL и мозг команды. Видит карту и код на 5 шагов вперёд.
 *  ДАНИЛИН ДМИТРИЙ — Anchor на точке B. Ждёт, не дёргается. Нет дедлоков.
 *  МОРОЗОВ ВЛАДИМИР — Энтри-фрагер. Заходит первым, чистит углы и баги.
 *  СЕНИН МАКСИМ — Король утилит. Смоки, флешки, логи и стабильный деплой.
*
 *  Bleach — чистят лобби в ноль. Squid Game — враги играют на выживание.
 *  Game 2 — первая была слишком лёгкой. Каждый раунд — хардкор.
 *  Код писался под крики "One tap!" и звон банок. Без согласия команды
 *  не копипастить. Иначе — вечный whiff и падение рейтинга Faceit.
 *
 *  RUSH B, NO STOP! СЛАВА CS:BSG2!
 *======================================================================*/

using Backend.Models;
using System.Globalization;

namespace Backend;

public static class DnsDataLoader
{
    private const string FeedbackPath = "user_feedback.csv";

    public static List<DnsData> LoadFromCsv(string csvPath)
    {
        var records = new List<DnsData>();

        foreach (var line in File.ReadLines(csvPath).Skip(1))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var lastComma = line.LastIndexOf(',');
            if (lastComma <= 0) continue;

            var rawUrl = line[..lastComma].Trim('"');
            var typeStr = line[(lastComma + 1)..].Trim();
            var domain = DnsFeatureExtractor.ExtractDomain(rawUrl);

            if (domain == null) continue;

            var isLegitimate = typeStr.Equals("legitimate", StringComparison.OrdinalIgnoreCase) ||
                              typeStr is "1" or "true";

            var features = DnsFeatureExtractor.ExtractFeatures(domain);
            features.ClassLabel = isLegitimate;
            records.Add(features);
        }

        return records;
    }

    public static List<DnsData> MergeWithUserFeedback(List<DnsData> existing)
    {
        if (!File.Exists(FeedbackPath)) return existing;

        var existingUrls = new HashSet<string>(existing.Select(p => p.Url));
        var result = new List<DnsData>(existing);

        foreach (var line in File.ReadLines(FeedbackPath).Skip(1))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var parts = line.Split(',');
            if (parts.Length < 27) continue;

            var domain = parts[0].Trim().ToLowerInvariant();
            if (existingUrls.Contains(domain)) continue;


            var classLabelValue = parts[^1].Trim(); // Last column
            var isLegitimate = classLabelValue == "1" ||
                              classLabelValue.Equals("true", StringComparison.OrdinalIgnoreCase);

            var features = new DnsData
            {
                Url = domain,
                DomainNameLength = float.Parse(parts[1], CultureInfo.InvariantCulture),
                UrlEntropy = float.Parse(parts[2], CultureInfo.InvariantCulture),
                PercentageNumericChars = float.Parse(parts[3], CultureInfo.InvariantCulture),
                DotCount = float.Parse(parts[4], CultureInfo.InvariantCulture),
                TokenCount = float.Parse(parts[5], CultureInfo.InvariantCulture),
                SubdomainCount = float.Parse(parts[6], CultureInfo.InvariantCulture),
                HasHyphenInDomain = float.Parse(parts[7], CultureInfo.InvariantCulture),
                NumberOfDigits = float.Parse(parts[8], CultureInfo.InvariantCulture),
                TldPopularity = float.Parse(parts[9], CultureInfo.InvariantCulture),
                TldLength = float.Parse(parts[10], CultureInfo.InvariantCulture),
                HyphenRatio = float.Parse(parts[11], CultureInfo.InvariantCulture),
                VeryShortTokenCount = float.Parse(parts[12], CultureInfo.InvariantCulture),
                AverageTokenLength = float.Parse(parts[13], CultureInfo.InvariantCulture),
                HasBrandPrefix = float.Parse(parts[14], CultureInfo.InvariantCulture),
                DigitToLengthRatio = float.Parse(parts[15], CultureInfo.InvariantCulture),
                ConsonantClusterScore = float.Parse(parts[16], CultureInfo.InvariantCulture),
                IsAllSubdomain = float.Parse(parts[17], CultureInfo.InvariantCulture),
                IsRandomString = float.Parse(parts[18], CultureInfo.InvariantCulture),
                RepeatedCharScore = float.Parse(parts[19], CultureInfo.InvariantCulture),
                VowelConsonantRatio = float.Parse(parts[20], CultureInfo.InvariantCulture),
                UnigramRarity = float.Parse(parts[21], CultureInfo.InvariantCulture),
                LevenshteinToBrands = float.Parse(parts[22], CultureInfo.InvariantCulture),
                BigramEnglishScore = float.Parse(parts[23], CultureInfo.InvariantCulture),
                CharacterTransitionScore = float.Parse(parts[24], CultureInfo.InvariantCulture),
                RepeatedNGramScore = float.Parse(parts[25], CultureInfo.InvariantCulture),
                ClassLabel = isLegitimate
            };

            result.Add(features);
        }

        return result;
    }

    public static List<DnsData> BalanceDataset(List<DnsData> records, int? seed = null)
    {
        if (records == null || records.Count == 0)
            return records;

        var legitimate = records.Where(r => r.ClassLabel).ToList();
        var suspicious = records.Where(r => !r.ClassLabel).ToList();

        var targetCount = Math.Min(legitimate.Count, suspicious.Count);

        var random = seed.HasValue ? new Random(seed.Value) : new Random();

        var balancedLegitimate = legitimate.Count > targetCount
            ? legitimate.OrderBy(x => random.Next()).Take(targetCount).ToList()
            : legitimate;

        var balancedSuspicious = suspicious.Count > targetCount
            ? suspicious.OrderBy(x => random.Next()).Take(targetCount).ToList()
            : suspicious;

        var balanced = new List<DnsData>();
        balanced.AddRange(balancedLegitimate);
        balanced.AddRange(balancedSuspicious);

        // Shuffle to mix legitimate and suspicious
        balanced = balanced.OrderBy(x => random.Next()).ToList();

        Console.WriteLine($"Dataset balanced: {balancedLegitimate.Count} legit, {balancedSuspicious.Count} susp (total: {balanced.Count})");

        return balanced;
    }

    public static void SaveRecordsToCsv(string path, IEnumerable<DnsData> records)
    {
        const string header = "Url,DomainNameLength,UrlEntropy,PercentageNumericChars,DotCount,TokenCount,SubdomainCount,HasHyphenInDomain,NumberOfDigits,TldPopularity,TldLength,HyphenRatio,VeryShortTokenCount,AverageTokenLength,HasBrandPrefix,DigitToLengthRatio,ConsonantClusterScore,IsAllSubdomain,IsRandomString,RepeatedCharScore,VowelConsonantRatio,UnigramRarity,LevenshteinToBrands,BigramEnglishScore,CharacterTransitionScore,RepeatedNGramScore,ClassLabel";

        using var sw = new StreamWriter(path);
        sw.WriteLine(header);

        var ci = CultureInfo.InvariantCulture;
        foreach (var r in records)
        {
            sw.WriteLine($"{r.Url},{r.DomainNameLength},{r.UrlEntropy.ToString(ci)},{r.PercentageNumericChars.ToString(ci)},{r.DotCount},{r.TokenCount},{r.SubdomainCount},{r.HasHyphenInDomain},{r.NumberOfDigits},{r.TldPopularity},{r.TldLength},{r.HyphenRatio.ToString(ci)},{r.VeryShortTokenCount},{r.AverageTokenLength.ToString(ci)},{r.HasBrandPrefix},{r.DigitToLengthRatio.ToString(ci)},{r.ConsonantClusterScore.ToString(ci)},{r.IsAllSubdomain},{r.IsRandomString},{r.RepeatedCharScore.ToString(ci)},{r.VowelConsonantRatio.ToString(ci)},{r.UnigramRarity.ToString(ci)},{r.LevenshteinToBrands.ToString(ci)},{r.BigramEnglishScore.ToString(ci)},{r.CharacterTransitionScore.ToString(ci)},{r.RepeatedNGramScore.ToString(ci)},{(r.ClassLabel ? 1 : 0)}");
        }
    }

    public static void SaveUserFeedback(DnsData features, bool isLegitimate)
    {
        const string header = "Url,DomainNameLength,UrlEntropy,PercentageNumericChars,DotCount,TokenCount,SubdomainCount,HasHyphenInDomain,NumberOfDigits,TldPopularity,TldLength,HyphenRatio,VeryShortTokenCount,AverageTokenLength,HasBrandPrefix,DigitToLengthRatio,ConsonantClusterScore,IsAllSubdomain,IsRandomString,RepeatedCharScore,VowelConsonantRatio,UnigramRarity,LevenshteinToBrands,BigramEnglishScore,CharacterTransitionScore,RepeatedNGramScore,ClassLabel";

        if (!File.Exists(FeedbackPath))
            File.WriteAllLines(FeedbackPath, new[] { header });

        if (File.ReadLines(FeedbackPath).Skip(1).Select(l => l.Split(',')[0])
            .Any(d => d.Equals(features.Url, StringComparison.OrdinalIgnoreCase)))
            return;

        var ci = CultureInfo.InvariantCulture;
        var csvLine = string.Join(",",
            features.Url,
            features.DomainNameLength,
            features.UrlEntropy.ToString(ci),
            features.PercentageNumericChars.ToString(ci),
            features.DotCount,
            features.TokenCount,
            features.SubdomainCount,
            features.HasHyphenInDomain,
            features.NumberOfDigits,
            features.TldPopularity,
            features.TldLength,
            features.HyphenRatio.ToString(ci),
            features.VeryShortTokenCount,
            features.AverageTokenLength.ToString(ci),
            features.HasBrandPrefix,
            features.DigitToLengthRatio.ToString(ci),
            features.ConsonantClusterScore.ToString(ci),
            features.IsAllSubdomain,
            features.IsRandomString,
            features.RepeatedCharScore.ToString(ci),
            features.VowelConsonantRatio.ToString(ci),
            features.UnigramRarity.ToString(ci),
            features.LevenshteinToBrands.ToString(ci),
            features.BigramEnglishScore.ToString(ci),
            features.CharacterTransitionScore.ToString(ci),
            features.RepeatedNGramScore.ToString(ci),
            isLegitimate ? "1" : "0");

        File.AppendAllLines(FeedbackPath, new[] { csvLine });
    }

    public static List<DnsData> RemoveDuplicates(List<DnsData> records)
    {
        return records.GroupBy(r => (r.Url, r.ClassLabel))
                      .Select(g => g.First())
                      .ToList();
    }
}