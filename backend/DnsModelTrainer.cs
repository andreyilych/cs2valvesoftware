using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers.LightGbm;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace Backend;

public class DnsSuspicionModel
{
    private readonly MLContext _mlContext;
    private ITransformer _model;
    private PredictionEngine<DomainFeature, DomainPrediction> _predictionEngine;
    private const string ModelPath = "dns_suspicion_model.zip";

    // === СТРУКТУРА СООТВЕТСТВУЕТ ВАШЕМУ CSV (11 колонок) ===
    public class DomainFeature
    {
        public float NameLength { get; set; }
        public float DotCount { get; set; }      // <-- Была пропущена
        public float Entropy { get; set; }
        public float DigitRatio { get; set; }
        public float ConsonantRatio { get; set; }
        public float HasHyphen { get; set; }
        public float TldRisk { get; set; }
        public float SubdomainCount { get; set; }
        public float TldLength { get; set; }
        public bool IsMalicious { get; set; }
    }

    public class DomainPrediction
    {
        [ColumnName("PredictedLabel")] public bool IsLegitimate { get; set; }
        public float Probability { get; set; }
        public float Score { get; set; }
        public string Verdict => IsLegitimate ? "Легитимный" : "Подозрительный";
    }

    public DnsSuspicionModel() => _mlContext = new MLContext(seed: 42);

    public void Train(string csvPath)
    {
        Console.WriteLine($"📥 Обучение модели из {csvPath}...");
        if (!File.Exists(csvPath)) throw new FileNotFoundException("CSV не найден", csvPath);

        var lines = File.ReadAllLines(csvPath);
        var cleanData = new List<DomainFeature>();

        // Пропускаем заголовок
        for (int i = 1; i < lines.Length; i++)
        {
            var parts = lines[i].Split(',');
            // 🔥 ИСПРАВЛЕНО: в вашем CSV 11 колонок, а не 10
            if (parts.Length < 11) continue;

            cleanData.Add(new DomainFeature
            {
                NameLength = float.Parse(parts[1], CultureInfo.InvariantCulture),
                DotCount = float.Parse(parts[2], CultureInfo.InvariantCulture),      // <-- ИСПРАВЛЕНО
                Entropy = float.Parse(parts[3], CultureInfo.InvariantCulture),       // <-- ИСПРАВЛЕНО
                DigitRatio = float.Parse(parts[4], CultureInfo.InvariantCulture),    // <-- ИСПРАВЛЕНО
                ConsonantRatio = float.Parse(parts[5], CultureInfo.InvariantCulture),// <-- ИСПРАВЛЕНО
                HasHyphen = float.Parse(parts[6], CultureInfo.InvariantCulture),     // <-- ИСПРАВЛЕНО
                TldRisk = float.Parse(parts[7], CultureInfo.InvariantCulture),       // <-- ИСПРАВЛЕНО
                SubdomainCount = float.Parse(parts[8], CultureInfo.InvariantCulture),// <-- ИСПРАВЛЕНО
                TldLength = float.Parse(parts[9], CultureInfo.InvariantCulture),     // <-- ИСПРАВЛЕНО
                IsMalicious = float.Parse(parts[10], CultureInfo.InvariantCulture) >= 0.5f // <-- ИСПРАВЛЕНО
            });
        }

        Console.WriteLine($"✅ Загружено {cleanData.Count} валидных строк.");
        if (cleanData.Count == 0) throw new Exception("CSV пуст после фильтрации. Проверьте колонки.");

        var dataView = _mlContext.Data.LoadFromEnumerable(cleanData);

        var pipeline = _mlContext.Transforms.Concatenate("Features",
                nameof(DomainFeature.NameLength), nameof(DomainFeature.DotCount),
                nameof(DomainFeature.Entropy), nameof(DomainFeature.DigitRatio),
                nameof(DomainFeature.ConsonantRatio), nameof(DomainFeature.HasHyphen),
                nameof(DomainFeature.TldRisk), nameof(DomainFeature.SubdomainCount),
                nameof(DomainFeature.TldLength))
            .Append(_mlContext.BinaryClassification.Trainers.LightGbm(
                labelColumnName: nameof(DomainFeature.IsMalicious),
                featureColumnName: "Features",
                numberOfLeaves: 31, numberOfIterations: 150, learningRate: 0.1f))
            .Append(_mlContext.BinaryClassification.Calibrators.Platt(
                labelColumnName: nameof(DomainFeature.IsMalicious), scoreColumnName: "Score"));

        Console.WriteLine("🧠 Обучение LightGBM...");
        _model = pipeline.Fit(dataView);

        _mlContext.Model.Save(_model, dataView.Schema, ModelPath);
        _predictionEngine = _mlContext.Model.CreatePredictionEngine<DomainFeature, DomainPrediction>(_model);

        var predictions = _model.Transform(dataView);

        // 🔥 ИСПРАВЛЕНО: явно указываем имя колонки-метки
        var metrics = _mlContext.BinaryClassification.Evaluate(
            predictions,
            labelColumnName: nameof(DomainFeature.IsMalicious));
        Console.WriteLine($"📊 Accuracy: {metrics.Accuracy:P2} | AUC: {metrics.AreaUnderRocCurve:P2}");
    }

    public void LoadModel(string path = ModelPath)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Модель не найдена", path);
        _model = _mlContext.Model.Load(path, out _);
        _predictionEngine = _mlContext.Model.CreatePredictionEngine<DomainFeature, DomainPrediction>(_model);
    }

    public DomainPrediction PredictDomain(string domain)
    {
        var features = ExtractFeatures(domain);
        var raw = _predictionEngine.Predict(features);

        float prob = raw.Probability;
        string name = domain.Split('.')[0];

        if (IsTyposquatting(name)) prob = Math.Min(prob, 0.15f);
        else if (features.Entropy > 3.8f && features.NameLength > 20) prob = Math.Min(prob, 0.2f);
        else if (features.TldRisk > 0.5f && features.DigitRatio > 0.1f) prob = Math.Min(prob, 0.3f);
        else if (features.NameLength < 10 && features.TldRisk == 0f && features.DigitRatio == 0f && !name.Contains('-'))
            prob = Math.Max(prob, 0.9f);

        return new DomainPrediction { IsLegitimate = prob >= 0.5f, Probability = prob, Score = raw.Score };
    }

    private static DomainFeature ExtractFeatures(string domain)
    {
        domain = domain.ToLower().Trim();
        var parts = domain.Split('.');
        if (parts.Length < 2) return new DomainFeature();

        string tld = parts.Last();
        string name = string.Join(".", parts.Take(parts.Length - 1));
        int len = name.Length;
        int digits = name.Count(char.IsDigit);
        int vowels = name.Count(c => "aeiouyаеёиоуыэюя".Contains(c));
        int consonants = Math.Max(0, len - digits - vowels);

        var freq = new Dictionary<char, int>();
        foreach (var c in name) freq[c] = freq.GetValueOrDefault(c, 0) + 1;
        float entropy = 0;
        foreach (var count in freq.Values) { float p = (float)count / len; entropy -= p * (float)Math.Log2(p); }

        var risky = new HashSet<string> { "xyz", "pw", "tk", "top", "click", "work", "biz", "info", "loan", "cc", "ws" };
        float tldRisk = risky.Contains(tld) ? 1.0f : 0.0f;

        return new DomainFeature
        {
            NameLength = len,
            DotCount = domain.Count(c => c == '.'), // <-- ДОБАВЛЕНО
            Entropy = entropy,
            DigitRatio = len > 0 ? (float)digits / len : 0f,
            ConsonantRatio = len > 0 ? (float)consonants / len : 0f,
            HasHyphen = name.Contains('-') ? 1f : 0f,
            TldRisk = tldRisk,
            SubdomainCount = Math.Max(0, parts.Length - 2),
            TldLength = tld.Length
        };
    }

    private static bool IsTyposquatting(string name)
    {
        var brands = new[] { "google", "facebook", "amazon", "microsoft", "apple", "paypal", "netflix", "sberbank", "yandex" };
        foreach (var b in brands) if (Levenshtein(name, b) <= 2 && Math.Abs(name.Length - b.Length) <= 2) return true;
        return false;
    }

    private static int Levenshtein(string s, string t)
    {
        int n = s.Length, m = t.Length;
        var d = new int[n + 1, m + 1];
        for (int i = 0; i <= n; i++) d[i, 0] = i;
        for (int j = 0; j <= m; j++) d[0, j] = j;
        for (int i = 1; i <= n; i++)
            for (int j = 1; j <= m; j++)
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + (s[i - 1] == t[j - 1] ? 0 : 1));
        return d[n, m];
    }
}