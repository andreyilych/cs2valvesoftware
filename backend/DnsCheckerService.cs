using Microsoft.Extensions.Logging;

namespace Backend.Services;

public class DnsCheckerService
{
    private readonly DnsSuspicionModel _model;
    private readonly ILogger<DnsCheckerService> _logger;
    private static readonly object _lock = new();
    private static bool _isInitialized = false;

    public DnsCheckerService(ILogger<DnsCheckerService> logger)
    {
        _logger = logger;
        _model = new DnsSuspicionModel();

        lock (_lock)
        {
            if (!_isInitialized)
            {
                string modelPath = Path.Combine(AppContext.BaseDirectory, "dns_suspicion_model.zip");
                string csvPath = Path.Combine(AppContext.BaseDirectory, "legitphish.csv");

                if (File.Exists(modelPath))
                {
                    _logger.LogInformation("Загружаем модель из {Path}", modelPath);
                    _model.LoadModel(modelPath);
                }
                else if (File.Exists(csvPath))
                {
                    _logger.LogWarning("Модель не найдена. Обучаем из {Path}", csvPath);
                    _model.Train(csvPath);
                }
                else
                {
                    _logger.LogError("Нет ни модели, ни датасета!");
                    throw new FileNotFoundException($"Нет файлов: {modelPath} или {csvPath}");
                }

                _isInitialized = true;
            }
        }
    }

    public DnsCheckResult CheckDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Домен пустой.");

        domain = domain.Trim().ToLowerInvariant();

        if (domain.Contains("://"))
        {
            try { domain = new Uri(domain).Host; }
            catch { }
        }
        if (domain.Contains('/'))
            domain = domain[..domain.IndexOf('/')];

        _logger.LogInformation("Проверка: {Domain}", domain);

        var prediction = _model.PredictDomain(domain);

        return new DnsCheckResult
        {
            Domain = domain,
            IsSuspicious = !prediction.IsLegitimate,
            IsLegitimate = prediction.IsLegitimate,
            Probability = prediction.Probability,
            Verdict = prediction.Verdict,
            CheckedAt = DateTime.UtcNow
        };
    }
}

public class DnsCheckResult
{
    public string Domain { get; set; } = "";
    public bool IsSuspicious { get; set; }
    public bool IsLegitimate { get; set; }
    public float Probability { get; set; }
    public string Verdict { get; set; } = "";
    public DateTime CheckedAt { get; set; }
}