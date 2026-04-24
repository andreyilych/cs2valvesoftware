using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers.LightGbm;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Backend;

public class DnsSuspicionModel
{
    private readonly MLContext _mlContext;
    private ITransformer _model;
    private PredictionEngine<DomainFeature, DomainPrediction> _predictionEngine;
    private const string ModelPath = "dns_suspicion_model.zip";

    // === СТРУКТУРА ДАННЫХ (СОВПАДАЕТ С ВАШИМ CSV) ===
    public class DomainFeature
    {
        [LoadColumn(0)] public string Domain { get; set; } = "";
        [LoadColumn(1)] public float NameLength { get; set; }
        [LoadColumn(2)] public float Entropy { get; set; }
        [LoadColumn(3)] public float DigitRatio { get; set; }
        [LoadColumn(4)] public float ConsonantRatio { get; set; }
        [LoadColumn(5)] public float HasHyphen { get; set; }
        [LoadColumn(6)] public float TldRisk { get; set; }
        [LoadColumn(7)] public float SubdomainCount { get; set; }
        [LoadColumn(8)] public float TldLength { get; set; }
        [LoadColumn(9)] public bool IsMalicious { get; set; }
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

        var dataView = _mlContext.Data.LoadFromTextFile<DomainFeature>(csvPath, hasHeader: true, separatorChar: ',');

        // Пайплайн: Признаки -> LightGBM -> Калибровка вероятностей
        var pipeline = _mlContext.Transforms.Concatenate("Features",
                nameof(DomainFeature.NameLength), nameof(DomainFeature.Entropy),
                nameof(DomainFeature.DigitRatio), nameof(DomainFeature.ConsonantRatio),
                nameof(DomainFeature.HasHyphen), nameof(DomainFeature.TldRisk),
                nameof(DomainFeature.SubdomainCount), nameof(DomainFeature.TldLength))
            .Append(_mlContext.BinaryClassification.Trainers.LightGbm(
                labelColumnName: nameof(DomainFeature.IsMalicious),
                featureColumnName: "Features",
                numberOfLeaves: 31, numberOfIterations: 150, learningRate: 0.1f))
            .Append(_mlContext.BinaryClassification.Calibrators.Platt(
                labelColumnName: nameof(DomainFeature.IsMalicious), scoreColumnName: "Score"));

        Console.WriteLine("🧠 Обучение...");
        _model = pipeline.Fit(dataView);
        _mlContext.Model.Save(_model, dataView.Schema, ModelPath);
        _predictionEngine = _mlContext.Model.CreatePredictionEngine<DomainFeature, DomainPrediction>(_model);

        var metrics = _mlContext.BinaryClassification.Evaluate(_model.Transform(dataView));
        Console.WriteLine($"✅ Accuracy: {metrics.Accuracy:P2} | AUC: {metrics.AreaUnderRocCurve:P2}");
    }

    public void LoadModel(string path = ModelPath)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Модель не найдена", path);
        _model = _mlContext.Model.Load(path, out _);
        _predictionEngine = _mlContext.Model.CreatePredictionEngine<DomainFeature, DomainPrediction>(_model);
    }

    // === ГЛАВНЫЙ МЕТОД ПРОВЕРКИ ===
    public DomainPrediction PredictDomain(string domain)
    {
        // 1. Извлекаем признаки так же, как в Python-скрипте
        var features = ExtractFeatures(domain);

        // 2. Получаем сырое предсказание от ML
        var raw = _predictionEngine.Predict(features);

        // 3. Применяем эвристики поверх ML (для защиты от тайпсквоттинга и DGA)
        float prob = raw.Probability;
        string name = domain.Split('.')[0]; // Основная часть
        string tld = domain.Split('.').Last();

        // 🔴 Тайпсквоттинг (gooogle -> google)
        if (IsTyposquatting(name)) prob = Math.Min(prob, 0.15f);

        // 🔴 Случайные длинные домены (DGA)
        else if (features.Entropy > 3.8 && features.NameLength > 20) prob = Math.Min(prob, 0.2f);

        // 🔴 Рисковая зона + цифры
        else if (features.TldRisk > 0.5 && features.DigitRatio > 0.1) prob = Math.Min(prob, 0.3f);

        // 🟢 Чистый короткий домен
        else if (features.NameLength < 10 && features.TldRisk == 0 && features.DigitRatio == 0 && !name.Contains('-'))
            prob = Math.Max(prob, 0.9f);

        return new DomainPrediction
        {
            IsLegitimate = prob >= 0.5f,
            Probability = prob,
            Score = raw.Score
        };
    }

    // === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===
    private static DomainFeature ExtractFeatures(string domain)
    {
        domain = domain.ToLower().Trim();
        var parts = domain.Split('.');
        if (parts.Length < 2) return new DomainFeature { Domain = domain }; // Fallback

        string tld = parts.Last();
        string name = string.Join(".", parts.Take(parts.Length - 1)); // Имя с поддоменами

        int len = name.Length;
        int digits = name.Count(char.IsDigit);
        int vowels = name.Count(c => "aeiouyаеёиоуыэюя".Contains(c));
        int consonants = Math.Max(0, len - digits - vowels);

        // Энтропия
        var freq = new Dictionary<char, int>();
        foreach (var c in name) freq[c] = freq.GetValueOrDefault(c, 0) + 1;
        float entropy = 0;
        foreach (var count in freq.Values) { float p = (float)count / len; entropy -= p * (float)Math.Log2(p); }

        // Риск TLD
        var risky = new HashSet<string> { "xyz", "pw", "tk", "top", "click", "work", "biz", "info", "loan", "cc", "ws" };
        float tldRisk = risky.Contains(tld) ? 1.0f : 0.0f;

        return new DomainFeature
        {
            Domain = domain,
            NameLength = len,
            Entropy = entropy,
            DigitRatio = len > 0 ? (float)digits / len : 0,
            ConsonantRatio = len > 0 ? (float)consonants / len : 0,
            HasHyphen = name.Contains('-') ? 1 : 0,
            TldRisk = tldRisk,
            SubdomainCount = Math.Max(0, parts.Length - 2),
            TldLength = tld.Length,
            IsMalicious = false // Не используется при предсказании
        };
    }

    private static bool IsTyposquatting(string name)
    {
        var brands = new[] { "google", "facebook", "amazon", "microsoft", "apple", "paypal", "netflix", "sberbank", "yandex", "tinkoff" };
        foreach (var b in brands)
        {
            if (Levenshtein(name, b) <= 2 && Math.Abs(name.Length - b.Length) <= 2) return true;
        }
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