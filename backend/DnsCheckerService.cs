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
using Microsoft.Extensions.Logging;

namespace Backend.Services;

public class DnsCheckerService
{
    private readonly DnsSuspicionModel _model;
    private readonly ILogger<DnsCheckerService> _logger;
    private static readonly Lock _lock = new();
    private static bool _isInitialized;

    public ModelMetrics? LastModelMetrics { get; private set; }

    public DnsCheckerService(ILogger<DnsCheckerService> logger)
    {
        _logger = logger;
        _model = new DnsSuspicionModel();

        lock (_lock)
        {
            if (_isInitialized) return;

            var modelPath = Path.Combine(AppContext.BaseDirectory, "dns_suspicion_model.zip");
            var csvPath = Path.Combine(AppContext.BaseDirectory, "legitphish.csv");

            if (File.Exists(csvPath))
            {
                _logger.LogInformation("Training model from {Path}", csvPath);
                _model.Train(csvPath);
                LastModelMetrics = _model.EvaluateModel("metrics.csv");
            }
            else if (File.Exists(modelPath))
            {
                _logger.LogInformation("Loading existing model from {Path}", modelPath);
                // TODO: Implement model loading if needed
            }
            else
            {
                _logger.LogError("No model or dataset found at {ModelPath} or {CsvPath}", modelPath, csvPath);
                throw new FileNotFoundException($"Required files missing: {modelPath} or {csvPath}");
            }

            _isInitialized = true;
        }
    }

    public DnsCheckResult CheckDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Domain cannot be empty.");

        domain = ExtractHost(domain);
        _logger.LogInformation("Checking domain: {Domain}", domain);

        var prediction = _model.Predict(domain);

        return new DnsCheckResult
        {
            Domain = domain,
            IsLegitimate = prediction.IsLegitimate,
            Probability = prediction.Probability,
            Verdict = prediction.Verdict,
            CheckedAt = DateTime.UtcNow
        };
    }

    private static string ExtractHost(string input)
    {
        input = input.Trim().ToLowerInvariant();

        if (input.Contains("://"))
        {
            try { input = new Uri(input).Host; }
            catch { }
        }

        var slashIndex = input.IndexOf('/');
        return slashIndex > 0 ? input[..slashIndex] : input;
    }
}

public class DnsCheckResult
{
    public string Domain { get; set; } = "";
    public bool IsLegitimate { get; set; }
    public float Probability { get; set; }
    public string Verdict { get; set; } = "";
    public DateTime CheckedAt { get; set; }
}