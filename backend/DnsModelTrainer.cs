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

public class ModelTrainer
{
    private readonly MLContext _mlContext;
    private const string ModelPath = "dns_suspicion_model.zip";
    private const string BalancedTrainCsvPath = "dns_train_balanced.csv";

    public ModelTrainer()
    {
        _mlContext = new MLContext(seed: 42);
    }

    public ITransformer Train(List<UrlData> trainingData)
    {
        DataLoader.SaveRecordsToCsv(BalancedTrainCsvPath, trainingData);

        var trainData = _mlContext.Data.LoadFromTextFile<UrlData>(
            BalancedTrainCsvPath,
            hasHeader: true,
            separatorChar: ',');

        var featureColumns = GetFeatureColumns();

        var pipeline = _mlContext.Transforms.Concatenate("Features", featureColumns)
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.BinaryClassification.Trainers.FastTree(
                labelColumnName: nameof(UrlData.ClassLabel),
                numberOfLeaves: 60,
                numberOfTrees: 500,
                learningRate: 0.05f,
                minimumExampleCountPerLeaf: 2));

        var model = pipeline.Fit(trainData);
        _mlContext.Model.Save(model, trainData.Schema, ModelPath);

        return model;
    }

    public ModelMetrics Evaluate(ITransformer model, string testCsvPath)
    {
        var testData = _mlContext.Data.LoadFromTextFile<UrlData>(
            testCsvPath,
            hasHeader: true,
            separatorChar: ',');

        var predictions = model.Transform(testData);
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

    public PredictionEngine<UrlData, Prediction> CreatePredictionEngine(ITransformer model)
    {
        return _mlContext.Model.CreatePredictionEngine<UrlData, Prediction>(model);
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