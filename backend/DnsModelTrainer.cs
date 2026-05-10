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

public class DnsModelTrainer
{
    private readonly MLContext _mlContext;
    private const string ModelPath = "dns_suspicion_model.zip";
    private const string BalancedTrainCsvPath = "dns_train_balanced.csv";

    public DnsModelTrainer()
    {
        _mlContext = new MLContext(seed: 42);
    }

    public ITransformer Train(List<DnsData> trainingData)
    {
        DnsDataLoader.SaveRecordsToCsv(BalancedTrainCsvPath, trainingData);

        var trainData = _mlContext.Data.LoadFromTextFile<DnsData>(
            BalancedTrainCsvPath,
            hasHeader: true,
            separatorChar: ',');

        var featureColumns = GetFeatureColumns();

        var pipeline = _mlContext.Transforms.Concatenate("Features", featureColumns)
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.BinaryClassification.Trainers.FastTree(
                labelColumnName: nameof(DnsData.ClassLabel),
                numberOfLeaves: 60,
                numberOfTrees: 500,
                learningRate: 0.05f,
                minimumExampleCountPerLeaf: 2));

        var model = pipeline.Fit(trainData);
        _mlContext.Model.Save(model, trainData.Schema, ModelPath);

        return model;
    }

    public DnsModelMetrics Evaluate(ITransformer model, string testCsvPath)
    {
        var testData = _mlContext.Data.LoadFromTextFile<DnsData>(
            testCsvPath,
            hasHeader: true,
            separatorChar: ',');

        var predictions = model.Transform(testData);
        var metrics = _mlContext.BinaryClassification.Evaluate(predictions,
            labelColumnName: nameof(DnsData.ClassLabel),
            scoreColumnName: "Score");

        return new DnsModelMetrics
        {
            Accuracy = metrics.Accuracy,
            Precision = metrics.PositivePrecision,
            F1Score = metrics.F1Score,
            AUC = metrics.AreaUnderRocCurve
        };
    }

    public PredictionEngine<DnsData, DnsPrediction> CreatePredictionEngine(ITransformer model)
    {
        return _mlContext.Model.CreatePredictionEngine<DnsData, DnsPrediction>(model);
    }

    private static string[] GetFeatureColumns() => new[]
    {
        nameof(DnsData.DomainNameLength), nameof(DnsData.UrlEntropy),
        nameof(DnsData.PercentageNumericChars), nameof(DnsData.DotCount),
        nameof(DnsData.TokenCount), nameof(DnsData.SubdomainCount),
        nameof(DnsData.HasHyphenInDomain), nameof(DnsData.NumberOfDigits),
        nameof(DnsData.TldPopularity), nameof(DnsData.TldLength),
        nameof(DnsData.HyphenRatio), nameof(DnsData.VeryShortTokenCount),
        nameof(DnsData.AverageTokenLength), nameof(DnsData.DigitToLengthRatio),
        nameof(DnsData.ConsonantClusterScore), nameof(DnsData.IsAllSubdomain),
        nameof(DnsData.IsRandomString), nameof(DnsData.RepeatedCharScore),
        nameof(DnsData.VowelConsonantRatio), nameof(DnsData.UnigramRarity),
        nameof(DnsData.LevenshteinToBrands), nameof(DnsData.BigramEnglishScore),
        nameof(DnsData.CharacterTransitionScore), nameof(DnsData.RepeatedNGramScore)
    };
}