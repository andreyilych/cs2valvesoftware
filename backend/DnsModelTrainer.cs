using Microsoft.ML;
using Microsoft.ML.Data;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Backend;

public class DnsSuspicionModel
{
    private readonly MLContext _mlContext;
    private ITransformer _model;
    private PredictionEngine<UrlData, Prediction> _predictionEngine;

    private const string ModelPath = "dns_suspicion_model.zip";

    public class UrlData
    {
        [LoadColumn(0)] public string Url { get; set; }
        [LoadColumn(1)] public float UrlLength { get; set; }
        [LoadColumn(2)] public float HasIpAddress { get; set; }
        [LoadColumn(3)] public float DotCount { get; set; }
        [LoadColumn(4)] public float HttpsFlag { get; set; }
        [LoadColumn(5)] public float UrlEntropy { get; set; }
        [LoadColumn(6)] public float TokenCount { get; set; }
        [LoadColumn(7)] public float SubdomainCount { get; set; }
        [LoadColumn(8)] public float QueryParamCount { get; set; }
        [LoadColumn(9)] public float TldLength { get; set; }
        [LoadColumn(10)] public float PathLength { get; set; }
        [LoadColumn(11)] public float HasHyphenInDomain { get; set; }
        [LoadColumn(12)] public float NumberOfDigits { get; set; }
        [LoadColumn(13)] public float TldPopularity { get; set; }
        [LoadColumn(14)] public float SuspiciousFileExtension { get; set; }
        [LoadColumn(15)] public float DomainNameLength { get; set; }
        [LoadColumn(16)] public float PercentageNumericChars { get; set; }
        [LoadColumn(17)] public bool ClassLabel { get; set; }
    }

    public class Prediction
    {
        [ColumnName("PredictedLabel")]
        public bool IsLegitimate { get; set; }

        public float Probability { get; set; }

        public float Score { get; set; }

        public string Verdict => IsLegitimate ? "Легитимный" : "Подозрительный";
    }

    public DnsSuspicionModel()
    {
        _mlContext = new MLContext(seed: 42);
    }

    public void Train(string csvPath)
    {
        Console.WriteLine("📥 Загружаем данные...");

        var lines = File.ReadAllLines(csvPath);
        Console.WriteLine($"   Всего строк: {lines.Length}");
        Console.WriteLine($"   Заголовок: {lines[0]}");

        int expectedColumns = 18;
        var problematicLines = new List<int>();
        for (int i = 1; i < lines.Length; i++)
        {
            var cols = lines[i].Split(',');
            if (cols.Length != expectedColumns)
                problematicLines.Add(i + 1);
        }

        if (problematicLines.Count > 0)
        {
            Console.WriteLine($"   ⚠ Найдено строк с неверным числом колонок: {problematicLines.Count}");
            Console.WriteLine($"   Первые 10 проблемных строк: {string.Join(", ", problematicLines.Take(10))}");
            Console.WriteLine("   🛠 Создаём очищенную копию CSV...");

            string cleanPath = Path.Combine(Path.GetDirectoryName(csvPath) ?? ".", "legitphish_clean.csv");
            using var writer = new StreamWriter(cleanPath);
            writer.WriteLine(lines[0]);

            int removed = 0;
            for (int i = 1; i < lines.Length; i++)
            {
                var cols = lines[i].Split(',');
                if (cols.Length == expectedColumns &&
                    (cols[17] == "0" || cols[17] == "1"))
                {
                    writer.WriteLine(lines[i]);
                }
                else
                {
                    removed++;
                }
            }
            Console.WriteLine($"   ✅ Удалено {removed} битых строк. Чистый файл: {cleanPath}");
            csvPath = cleanPath;
        }

        var dataView = _mlContext.Data.LoadFromTextFile<UrlData>(
            path: csvPath,
            hasHeader: true,
            separatorChar: ',');

        var preview = dataView.Preview(maxRows: 5);
        Console.WriteLine($"   ✅ Данные загружены. Колонок: {preview.Schema.Count}");

        var pipeline = _mlContext.Transforms.Concatenate(
                "Features",
                nameof(UrlData.UrlLength),
                nameof(UrlData.HasIpAddress),
                nameof(UrlData.DotCount),
                nameof(UrlData.HttpsFlag),
                nameof(UrlData.UrlEntropy),
                nameof(UrlData.TokenCount),
                nameof(UrlData.SubdomainCount),
                nameof(UrlData.QueryParamCount),
                nameof(UrlData.TldLength),
                nameof(UrlData.PathLength),
                nameof(UrlData.HasHyphenInDomain),
                nameof(UrlData.NumberOfDigits),
                nameof(UrlData.TldPopularity),
                nameof(UrlData.SuspiciousFileExtension),
                nameof(UrlData.DomainNameLength),
                nameof(UrlData.PercentageNumericChars))
            .Append(_mlContext.BinaryClassification.Trainers.FastTree(
                labelColumnName: nameof(UrlData.ClassLabel),
                featureColumnName: "Features",
                numberOfLeaves: 20,
                numberOfTrees: 100,
                minimumExampleCountPerLeaf: 10));

        Console.WriteLine("🧠 Обучаем модель LightGbm...");
        _model = pipeline.Fit(dataView);

        _mlContext.Model.Save(_model, dataView.Schema, ModelPath);
        Console.WriteLine($"💾 Модель сохранена: {ModelPath}");

        _predictionEngine = _mlContext.Model.CreatePredictionEngine<UrlData, Prediction>(_model);

        var predictions = _model.Transform(dataView);
        var metrics = _mlContext.BinaryClassification.Evaluate(
            predictions,
            labelColumnName: nameof(UrlData.ClassLabel),
            scoreColumnName: "Score");

        Console.WriteLine($"📊 Качество модели:");
        Console.WriteLine($"   Accuracy:  {metrics.Accuracy:P2}");
        Console.WriteLine($"   F1 Score:  {metrics.F1Score:P2}");
        Console.WriteLine($"   AUC:       {metrics.AreaUnderRocCurve:P2}");
    }

    public void LoadModel(string modelPath = ModelPath)
    {
        if (!File.Exists(modelPath))
            throw new FileNotFoundException($"Модель не найдена: {modelPath}. Сначала запустите Train().");

        Console.WriteLine($"📂 Загружаем модель из {modelPath}...");
        _model = _mlContext.Model.Load(modelPath, out var schema);
        _predictionEngine = _mlContext.Model.CreatePredictionEngine<UrlData, Prediction>(_model);
        Console.WriteLine("✅ Модель загружена.");
    }

    public Prediction Predict(UrlData urlData)
    {
        if (_predictionEngine == null)
            throw new InvalidOperationException("Модель не загружена. Вызовите Train() или LoadModel().");

        return _predictionEngine.Predict(urlData);
    }

    /// <summary>
    /// Извлечение признаков из URL в том же формате, что и датасет LegitPhish.
    /// Работает с полными URL (https://example.com/path?query=1).
    /// Если передан голый домен, добавляет https:// и / в конце.
    /// </summary>
    public static UrlData CreateFeaturesFromUrl(string input)
    {
        // Нормализация: датасет всегда содержит полный URL с протоколом и путём
        string url;
        if (!input.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !input.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            // Если это голый домен — делаем полный URL с https и /
            url = "https://" + input + "/";
        }
        else if (!input.EndsWith("/") && !input.Contains("?", StringComparison.OrdinalIgnoreCase))
        {
            // Если нет завершающего слеша и нет query — добавляем /
            url = input + "/";
        }
        else
        {
            url = input;
        }

        Uri uri;
        try { uri = new Uri(url); }
        catch { uri = new Uri("https://unknown.com/"); }

        string host = uri.Host;
        string fullUrl = uri.ToString();
        string pathAndQuery = uri.PathAndQuery; // /path?query
        string path = uri.AbsolutePath;          // /path
        string query = uri.Query;                // ?query или пусто

        // Извлекаем домен (без www и без TLD)
        string domainName = host;
        if (domainName.StartsWith("www."))
            domainName = domainName.Substring(4);

        // TLD — последняя часть после точки
        var hostParts = host.Split('.');
        string tld = hostParts.Length > 1 ? hostParts.Last() : host;

        // Проверка на IP-адрес
        bool isIp = System.Net.IPAddress.TryParse(host, out _);

        // Количество query-параметров (как в датасете: минимум 1, даже если их нет)
        int queryParamCount = 1; // в датасете всегда минимум 1
        if (!string.IsNullOrEmpty(query) && query.Length > 1)
        {
            var qParams = query.Substring(1).Split('&');
            queryParamCount = qParams.Length;
        }

        // Популярные TLD (как в датасете)
        var popularTlds = new HashSet<string> { "com", "org", "net", "edu", "gov", "co", "io", "ru", "uk", "de", "fr", "jp", "br", "au" };

        // Подозрительные расширения файлов
        var suspiciousExtensions = new HashSet<string> { ".exe", ".zip", ".scr", ".js", ".bat", ".vbs", ".dll", ".msi", ".apk" };

        bool hasSuspiciousExt = false;
        string pathLower = path.ToLowerInvariant();
        foreach (var ext in suspiciousExtensions)
        {
            if (pathLower.EndsWith(ext))
            {
                hasSuspiciousExt = true;
                break;
            }
        }

        // Токены: части URL, разделённые ./?=&-
        var tokens = fullUrl.Split(new[] { '/', '.', '?', '=', '&', '-' }, StringSplitOptions.RemoveEmptyEntries);
        int tokenCount = tokens.Length;

        // Энтропия Шеннона для полного URL
        float entropy = CalculateEntropy(fullUrl);

        // Длина пути
        int pathLength = path.Length;

        // Цифры
        int digitCount = fullUrl.Count(char.IsDigit);

        // Процент цифр
        float pctNumeric = fullUrl.Length > 0 ? (float)digitCount / fullUrl.Length * 100f : 0f;

        // Поддомены: количество точек в хосте минус точка перед TLD
        int dotCountInHost = host.Count(c => c == '.');
        int subdomainCount = Math.Max(0, dotCountInHost - 1); // минус точка перед TLD
        // Если www — это тоже субдомен, но в датасете он считается за поддомен
        // оставляем как есть

        return new UrlData
        {
            Url = url,
            UrlLength = fullUrl.Length,
            HasIpAddress = isIp ? 1f : 0f,
            DotCount = fullUrl.Count(c => c == '.'),
            HttpsFlag = uri.Scheme == "https" ? 1f : 0f,
            UrlEntropy = entropy,
            TokenCount = tokenCount,
            SubdomainCount = subdomainCount,
            QueryParamCount = queryParamCount,
            TldLength = tld.Length,
            PathLength = pathLength,
            HasHyphenInDomain = host.Contains('-') ? 1f : 0f,
            NumberOfDigits = digitCount,
            TldPopularity = popularTlds.Contains(tld.ToLower()) ? 1f : 0f,
            SuspiciousFileExtension = hasSuspiciousExt ? 1f : 0f,
            DomainNameLength = domainName.Length,
            PercentageNumericChars = pctNumeric
        };
    }

    private static float CalculateEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0f;
        var freq = new Dictionary<char, int>();
        foreach (char c in s)
        {
            if (freq.ContainsKey(c)) freq[c]++;
            else freq[c] = 1;
        }

        float entropy = 0f;
        int len = s.Length;
        foreach (var count in freq.Values)
        {
            float p = (float)count / len;
            entropy -= p * (float)Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>
    /// Предсказание с автоматической калибровкой для "голых" доменов.
    /// </summary>
    public Prediction PredictDomain(string domain)
    {
        var data = CreateFeaturesFromUrl(domain);
        var rawPrediction = Predict(data);

        // Признаки "чистого" домена
        bool isCleanDomain = data.PathLength <= 1
                          && data.QueryParamCount <= 1
                          && data.SuspiciousFileExtension == 0
                          && data.HasIpAddress == 0
                          && data.HasHyphenInDomain == 0
                          && data.NumberOfDigits <= 2
                          && data.PercentageNumericChars < 10;

        bool popularTld = data.TldPopularity == 1;
        bool shortDomain = data.DomainNameLength <= 15 && data.SubdomainCount <= 1;

        // === НОВОЕ: признаки "подозрительной случайности" ===
        bool highEntropy = data.UrlEntropy > 3.8f;
        bool longDomain = data.DomainNameLength > 20;
        bool hasMixedChars = data.NumberOfDigits > 0 && data.DomainNameLength > 10;

        // Случайный набор типа iuqerfsodp... — высокая энтропия + длинный домен
        bool looksRandom = highEntropy && longDomain;

        float adjustedProb = rawPrediction.Probability;

        // === ШТРАФ ЗА СЛУЧАЙНЫЙ ВИД ===
        if (looksRandom && data.DomainNameLength > 25)
        {
            // Очень длинный + высокая энтропия = почти наверняка подозрительный
            adjustedProb = Math.Min(adjustedProb, 0.15f);
        }
        else if (looksRandom)
        {
            // Просто случайный вид
            adjustedProb = Math.Min(adjustedProb, 0.35f);
        }
        // === БОНУС ЗА ЧИСТЫЙ ДОМЕН ===
        else if (isCleanDomain)
        {
            if (popularTld && shortDomain)
            {
                adjustedProb = Math.Max(adjustedProb, 0.85f);
            }
            else if (popularTld)
            {
                adjustedProb = Math.Max(adjustedProb, 0.70f);
            }
            else if (shortDomain)
            {
                adjustedProb = Math.Max(adjustedProb, 0.60f);
            }
        }

        return new Prediction
        {
            IsLegitimate = adjustedProb >= 0.5f,
            Probability = adjustedProb,
            Score = rawPrediction.Score
        };
    }
}