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

using Microsoft.ML;
using Backend.Models;

namespace Backend;

public class DnsSuspicionModel
{
    private readonly DnsModelTrainer _trainer;
    private ITransformer? _model;
    private PredictionEngine<DnsData, DnsPrediction>? _predictionEngine;

    public DnsSuspicionModel()
    {
        _trainer = new DnsModelTrainer();
    }

    public DnsModelMetrics EvaluateModel(string testCsvPath)
    {
        if (_model == null)
            throw new InvalidOperationException("Model not trained yet.");

        return _trainer.Evaluate(_model, testCsvPath);
    }

    public void Train(string rawCsvPath)
    {
        var processed = DnsDataLoader.LoadFromCsv(rawCsvPath);
        processed = DnsDataLoader.MergeWithUserFeedback(processed);
        processed = DnsDataLoader.RemoveDuplicates(processed);
        processed = DnsDataLoader.BalanceDataset(processed);

        _model = _trainer.Train(processed);
        _predictionEngine = _trainer.CreatePredictionEngine(_model);

        var legitCount = processed.Count(r => r.ClassLabel);
        var phishCount = processed.Count(r => !r.ClassLabel);

        Console.WriteLine($"Training completed. Records: {processed.Count} (legit: {legitCount}, susp: {phishCount})");
    }

    public DnsPrediction Predict(string domainOrUrl)
    {
        if (_predictionEngine == null)
            throw new InvalidOperationException("Model not loaded. Call Train() first.");

        var domain = DnsFeatureExtractor.ExtractDomain(domainOrUrl);
        if (domain == null)
            return new DnsPrediction { IsLegitimate = false, Probability = 0, Score = float.MinValue };

        var features = DnsFeatureExtractor.ExtractFeatures(domain);
        var result = _predictionEngine.Predict(features);

        DnsDataLoader.SaveUserFeedback(features, result.IsLegitimate);
        return result;
    }
}