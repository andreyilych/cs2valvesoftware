// DnsModelTrainer.cs
using Microsoft.ML;
using Microsoft.ML.Data;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Backend;

public struct ModelMetrics
{
    public double Accuracy { get; set; }
    public double Precision { get; set; }
    public double F1Score { get; set; }
    public double AUC { get; set; }
}

public class DnsSuspicionModel
{
    private readonly MLContext _mlContext;
    private ITransformer? _model;
    private PredictionEngine<UrlData, Prediction>? _predictionEngine;

    private const string ModelPath = "dns_suspicion_model.zip";
    private const string FeedbackPath = "user_feedback.csv";
    private const string BalancedTrainCsvPath = "dns_train_balanced.csv";

    private static readonly HashSet<string> PopularTlds = new()
    {
        ".com", ".org", ".net", ".ru", ".de", ".uk", ".co.uk",
        ".fr", ".it", ".es", ".pl", ".nl", ".br", ".in", ".jp",
        ".cn", ".au", ".ca", ".cz", ".se", ".ch", ".at", ".be"
    };

    private static readonly HashSet<char> Vowels = new() { 'a', 'e', 'i', 'o', 'u', 'y' };
    private static readonly HashSet<char> Consonants = new()
    {
        'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm',
        'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'z'
    };

    private static readonly HashSet<string> CommonEnglishBigrams = new()
    {
        "th", "he", "in", "er", "an", "re", "nd", "on", "en", "at",
        "ou", "ed", "ha", "to", "or", "it", "is", "hi", "es", "ng"
    };

    private static readonly HashSet<string> PopularBrands = new()
    {
        "google", "facebook", "youtube", "yahoo", "amazon", "microsoft", "apple",
        "netflix", "twitter", "instagram", "linkedin", "whatsapp", "snapchat",
        "paypal", "ebay", "aliexpress", "walmart", "reddit", "twitch"
    };

    private static readonly HashSet<string> RareBigrams = new()
    {
        "zx", "zq", "qx", "qj", "jk", "kj", "xv", "vx", "wp", "pw",
        "qz", "jq", "qk", "wq", "jz", "zj", "xk", "kx"
    };

    public class UrlData
    {
        [LoadColumn(0)] public string Url { get; set; } = string.Empty;
        [LoadColumn(1)] public float DomainNameLength { get; set; }
        [LoadColumn(2)] public float UrlEntropy { get; set; }
        [LoadColumn(3)] public float PercentageNumericChars { get; set; }
        [LoadColumn(4)] public float DotCount { get; set; }
        [LoadColumn(5)] public float TokenCount { get; set; }
        [LoadColumn(6)] public float SubdomainCount { get; set; }
        [LoadColumn(7)] public float HasHyphenInDomain { get; set; }
        [LoadColumn(8)] public float NumberOfDigits { get; set; }
        [LoadColumn(9)] public float TldPopularity { get; set; }
        [LoadColumn(10)] public float TldLength { get; set; }
        [LoadColumn(11)] public float HyphenRatio { get; set; }
        [LoadColumn(12)] public float VeryShortTokenCount { get; set; }
        [LoadColumn(13)] public float AverageTokenLength { get; set; }
        [LoadColumn(14)] public float HasBrandPrefix { get; set; }
        [LoadColumn(15)] public float DigitToLengthRatio { get; set; }
        [LoadColumn(16)] public float ConsonantClusterScore { get; set; }
        [LoadColumn(17)] public float IsAllSubdomain { get; set; }
        [LoadColumn(18)] public float IsRandomString { get; set; }
        [LoadColumn(19)] public float RepeatedCharScore { get; set; }
        [LoadColumn(20)] public float VowelConsonantRatio { get; set; }
        [LoadColumn(21)] public float UnigramRarity { get; set; }
        [LoadColumn(22)] public float LevenshteinToBrands { get; set; }
        [LoadColumn(23)] public float BigramEnglishScore { get; set; }
        [LoadColumn(24)] public float CharacterTransitionScore { get; set; }
        [LoadColumn(25)] public float RepeatedNGramScore { get; set; }
        [LoadColumn(26)] public bool ClassLabel { get; set; }
    }

    public class Prediction
    {
        [ColumnName("PredictedLabel")] public bool IsLegitimate { get; set; }
        public float Probability { get; set; }
        public float Score { get; set; }
        public string Verdict => IsLegitimate ? "Безопасный" : "Вредоносный";
    }

    public DnsSuspicionModel()
    {
        _mlContext = new MLContext(seed: 42);
    }

    public ModelMetrics EvaluateModel(string testCsvPath)
    {
        var testData = _mlContext.Data.LoadFromTextFile<UrlData>(testCsvPath, hasHeader: true, separatorChar: ',');
        var predictions = _model!.Transform(testData);
        var metrics = _mlContext.BinaryClassification.Evaluate(predictions,
            labelColumnName: nameof(UrlData.ClassLabel),
            scoreColumnName: "Score");

        return new ModelMetrics
        {
            Accuracy = metrics.Accuracy,
            Precision = metrics.PositivePrecision,
            F1Score = metrics.F1Score,
            AUC = metrics.AreaUnderRocCurve
        };
    }

    public void Train(string rawCsvPath)
    {
        var processed = LoadAndProcessData(rawCsvPath);
        processed = AddUserFeedback(processed);
        processed = RemoveDuplicates(processed);

        SaveRecordsToCsv(BalancedTrainCsvPath, processed);

        var trainData = _mlContext.Data.LoadFromTextFile<UrlData>(BalancedTrainCsvPath, hasHeader: true, separatorChar: ',');

        var featureColumns = GetFeatureColumns();

        var pipeline = _mlContext.Transforms.Concatenate("Features", featureColumns)
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.BinaryClassification.Trainers.FastTree(
                labelColumnName: nameof(UrlData.ClassLabel),
                numberOfLeaves: 60,
                numberOfTrees: 500,
                learningRate: 0.05f,
                minimumExampleCountPerLeaf: 2));

        _model = pipeline.Fit(trainData);
        _mlContext.Model.Save(_model, trainData.Schema, ModelPath);
        _predictionEngine = _mlContext.Model.CreatePredictionEngine<UrlData, Prediction>(_model);

        var legitCount = processed.Count(r => r.ClassLabel);
        var phishCount = processed.Count(r => !r.ClassLabel);
        Console.WriteLine($"Training completed. Records: {processed.Count} (legit: {legitCount}, susp: {phishCount})");
    }

    public Prediction Predict(string domainOrUrl)
    {
        if (_predictionEngine == null)
            throw new InvalidOperationException("Model not loaded. Call Train() first.");

        var domain = ExtractDomain(domainOrUrl);
        if (domain == null)
            return new Prediction { IsLegitimate = false, Probability = 0, Score = float.MinValue };

        var features = CreateDomainFeatures(domain);
        var result = _predictionEngine.Predict(features);

        SaveUserFeedback(features, result.IsLegitimate);
        return result;
    }

    private static string? ExtractDomain(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;

        var clean = Regex.Replace(input.Trim().ToLower(), @"^(https?://)?(www\.)?", "");
        clean = clean.Split('/', '?', ':')[0];

        return clean.Contains('.') && !System.Net.IPAddress.TryParse(clean, out _) ? clean : null;
    }

    private static int LevenshteinDistance(string s1, string s2)
    {
        var costs = new int[s2.Length + 1];
        for (var i = 0; i <= s1.Length; i++)
        {
            var lastValue = i;
            for (var j = 0; j <= s2.Length; j++)
            {
                if (i == 0)
                    costs[j] = j;
                else if (j > 0)
                {
                    var newValue = costs[j - 1];
                    if (s1[i - 1] != s2[j - 1])
                        newValue = Math.Min(Math.Min(newValue, lastValue), costs[j]) + 1;
                    costs[j - 1] = lastValue;
                    lastValue = newValue;
                }
            }
            if (i > 0)
                costs[s2.Length] = lastValue;
        }
        return costs[s2.Length];
    }

    private static float CalculateLevenshteinToBrands(string domain)
    {
        var domainName = domain.Split('.')[0];
        if (domainName.Length < 4) return 0;

        var minDistance = PopularBrands
            .Select(brand => LevenshteinDistance(domainName, brand))
            .Min();

        return minDistance switch
        {
            <= 2 => 0.9f,
            <= 3 => 0.7f,
            <= 4 => 0.4f,
            _ => Math.Max(0, 1 - minDistance / 10f)
        };
    }

    private static float CalculateBigramEnglishScore(string s)
    {
        if (s.Length < 2) return 0;

        var commonBigramCount = 0;
        for (var i = 0; i < s.Length - 1; i++)
        {
            if (CommonEnglishBigrams.Contains(s.Substring(i, 2)))
                commonBigramCount++;
        }

        return (float)commonBigramCount / (s.Length - 1);
    }

    private static float CalculateCharacterTransitionScore(string s)
    {
        if (s.Length < 2) return 0;

        var abruptTransitions = 0;
        for (var i = 0; i < s.Length - 1; i++)
        {
            if (RareBigrams.Any(b => b[0] == s[i] && b[1] == s[i + 1]))
                abruptTransitions++;
        }

        return Math.Min(1.0f, abruptTransitions / 3.0f);
    }

    private static float CalculateRepeatedNGramScore(string s)
    {
        if (s.Length < 6) return 0;

        var repeats = 0;
        var seen = new HashSet<string>();

        for (var i = 0; i < s.Length - 2; i++)
        {
            var trigram = s.Substring(i, 3);
            if (seen.Contains(trigram))
                repeats++;
            else
                seen.Add(trigram);
        }

        return Math.Min(1.0f, repeats / 5.0f);
    }

    private static float CalculateEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;

        var length = s.Length;
        return (float)s.GroupBy(c => c)
            .Select(g => (float)g.Count() / length)
            .Sum(p => -p * Math.Log2(p));
    }

    private static float CalculateConsonantClusterScore(string domain, int totalChars)
    {
        var clusters = 0;
        var consecutive = 0;

        foreach (var c in domain)
        {
            if (Consonants.Contains(char.ToLower(c)))
            {
                consecutive++;
                if (consecutive >= 3) clusters++;
            }
            else
            {
                consecutive = 0;
            }
        }

        return Math.Min(1.0f, (float)clusters / Math.Max(1, totalChars / 3));
    }

    private static float CalculateRepeatedCharScore(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;

        var maxRepeat = 0;
        var currentRepeat = 1;
        var lastChar = '\0';

        foreach (var c in s)
        {
            if (c == lastChar)
            {
                currentRepeat++;
                maxRepeat = Math.Max(maxRepeat, currentRepeat);
            }
            else
            {
                currentRepeat = 1;
                lastChar = c;
            }
        }

        return Math.Min(1.0f, maxRepeat / 4.0f);
    }

    private static float CalculateVowelConsonantRatio(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0.5f;

        var vowels = s.Count(c => Vowels.Contains(c));
        var consonants = s.Count(c => Consonants.Contains(c));
        var total = vowels + consonants;

        return total == 0 ? 0.5f : (float)vowels / total;
    }

    private static bool IsRandomLookingString(string domainName, float bigramEnglishScore,
        float characterTransitionScore, float repeatedNGramScore)
    {
        if (domainName.Length < 8) return false;

        var entropy = CalculateEntropy(domainName);
        var repeatedCharScore = CalculateRepeatedCharScore(domainName);
        var vowelConsonantRatio = CalculateVowelConsonantRatio(domainName);

        var isHighEntropy = entropy > (domainName.Length > 15 ? 4.2 : 3.8);
        var isLowEnglishMatch = bigramEnglishScore < 0.3f;
        var isHighAbruptTransitions = characterTransitionScore > 0.4f;
        var isHighRepeats = repeatedNGramScore > 0.5f;
        var isExtremeVowelRatio = vowelConsonantRatio > 0.7f || vowelConsonantRatio < 0.2f;

        if (domainName.Length > 15)
            return (isHighEntropy && isLowEnglishMatch) ||
                   (isHighEntropy && isHighAbruptTransitions) ||
                   (isLowEnglishMatch && isHighRepeats);

        var trueCount = new[] { isHighEntropy, isLowEnglishMatch, isHighAbruptTransitions,
                                 isHighRepeats, isExtremeVowelRatio }.Count(v => v);

        return trueCount >= 3;
    }

    public UrlData CreateDomainFeatures(string domain)
    {
        if (string.IsNullOrEmpty(domain))
            throw new ArgumentNullException(nameof(domain));

        var domainName = domain.Split('.')[0];
        var tokens = domain.Split('.', '-');

        var digits = domain.Count(char.IsDigit);
        var totalChars = domain.Length;
        var hyphenCount = domain.Count(c => c == '-');
        var dotCount = domain.Count(c => c == '.');

        var veryShortTokens = tokens.Count(t => t.Length is <= 2 and > 0);
        var avgTokenLen = tokens.Length > 0 ? tokens.Average(t => (float)t.Length) : 0;
        var hyphenRatio = totalChars > 0 ? (float)hyphenCount / totalChars : 0;
        var digitToLengthRatio = totalChars > 0 ? (float)digits / totalChars : 0;

        var unigramRarity = Math.Min(1.0f, RareBigrams.Count(domainName.Contains) * 0.2f);
        var consonantClusterScore = CalculateConsonantClusterScore(domain, totalChars);

        var levenshteinToBrands = CalculateLevenshteinToBrands(domain);
        var bigramEnglishScore = CalculateBigramEnglishScore(domainName);
        var characterTransitionScore = CalculateCharacterTransitionScore(domainName);
        var repeatedNGramScore = CalculateRepeatedNGramScore(domainName);
        var isRandomString = IsRandomLookingString(domainName, bigramEnglishScore,
            characterTransitionScore, repeatedNGramScore);

        return new UrlData
        {
            Url = domain,
            DomainNameLength = totalChars,
            UrlEntropy = CalculateEntropy(domain),
            PercentageNumericChars = (float)digits / Math.Max(1, totalChars),
            DotCount = dotCount,
            TokenCount = tokens.Length,
            SubdomainCount = Math.Max(0, dotCount - 1),
            HasHyphenInDomain = hyphenCount > 0 ? 1f : 0f,
            NumberOfDigits = digits,
            TldPopularity = PopularTlds.Any(domain.EndsWith) ? 1f : 0f,
            TldLength = tokens.Last().Length,
            HyphenRatio = hyphenRatio,
            VeryShortTokenCount = veryShortTokens,
            AverageTokenLength = avgTokenLen,
            HasBrandPrefix = 0,
            DigitToLengthRatio = digitToLengthRatio,
            ConsonantClusterScore = consonantClusterScore,
            IsAllSubdomain = dotCount >= 2 ? 1f : 0f,
            IsRandomString = isRandomString ? 1f : 0f,
            RepeatedCharScore = CalculateRepeatedCharScore(domainName),
            VowelConsonantRatio = CalculateVowelConsonantRatio(domainName),
            UnigramRarity = unigramRarity,
            LevenshteinToBrands = levenshteinToBrands,
            BigramEnglishScore = bigramEnglishScore,
            CharacterTransitionScore = characterTransitionScore,
            RepeatedNGramScore = repeatedNGramScore
        };
    }

    private List<UrlData> LoadAndProcessData(string rawCsvPath)
    {
        var processed = new List<UrlData>();

        foreach (var line in File.ReadLines(rawCsvPath).Skip(1))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var lastComma = line.LastIndexOf(',');
            if (lastComma <= 0) continue;

            var rawUrl = line[..lastComma].Trim('"');
            var typeStr = line[(lastComma + 1)..].Trim();
            var domain = ExtractDomain(rawUrl);

            if (domain == null) continue;

            var isLegitimate = typeStr.Equals("legitimate", StringComparison.OrdinalIgnoreCase) ||
                              typeStr is "1" or "true";

            var features = CreateDomainFeatures(domain);
            features.ClassLabel = isLegitimate;
            processed.Add(features);
        }

        return processed;
    }

    private List<UrlData> AddUserFeedback(List<UrlData> existing)
    {
        if (!File.Exists(FeedbackPath)) return existing;

        var existingUrls = new HashSet<string>(existing.Select(p => p.Url));
        var result = new List<UrlData>(existing);

        foreach (var line in File.ReadLines(FeedbackPath).Skip(1))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var parts = line.Split(',');
            if (parts.Length < 2) continue;

            var domain = parts[0].Trim().ToLowerInvariant();
            if (existingUrls.Contains(domain)) continue;

            var isLegitimate = parts[1].Trim().Equals("legitimate", StringComparison.OrdinalIgnoreCase) ||
                              parts[1].Trim() is "1" or "true";

            var features = CreateDomainFeatures(domain);
            features.ClassLabel = isLegitimate;
            result.Add(features);
        }

        return result;
    }

    private static List<UrlData> RemoveDuplicates(List<UrlData> records)
    {
        return records.GroupBy(r => (r.Url, r.ClassLabel))
                      .Select(g => g.First())
                      .ToList();
    }

    private static void SaveUserFeedback(UrlData features, bool isLegitimate)
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

    private static void SaveRecordsToCsv(string path, IEnumerable<UrlData> records)
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

    private static string[] GetFeatureColumns() => new[]
    {
        nameof(UrlData.DomainNameLength), nameof(UrlData.UrlEntropy),
        nameof(UrlData.PercentageNumericChars), nameof(UrlData.DotCount),
        nameof(UrlData.TokenCount), nameof(UrlData.SubdomainCount),
        nameof(UrlData.HasHyphenInDomain), nameof(UrlData.NumberOfDigits),
        nameof(UrlData.TldPopularity), nameof(UrlData.TldLength),
        nameof(UrlData.HyphenRatio), nameof(UrlData.VeryShortTokenCount),
        nameof(UrlData.AverageTokenLength), nameof(UrlData.DigitToLengthRatio),
        nameof(UrlData.ConsonantClusterScore), nameof(UrlData.IsAllSubdomain),
        nameof(UrlData.IsRandomString), nameof(UrlData.RepeatedCharScore),
        nameof(UrlData.VowelConsonantRatio), nameof(UrlData.UnigramRarity),
        nameof(UrlData.LevenshteinToBrands), nameof(UrlData.BigramEnglishScore),
        nameof(UrlData.CharacterTransitionScore), nameof(UrlData.RepeatedNGramScore)
    };
}