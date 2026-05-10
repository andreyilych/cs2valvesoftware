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

using Microsoft.ML.Data;

namespace Backend.Models;

public struct DnsModelMetrics
{
    public double Accuracy { get; set; }
    public double Precision { get; set; }
    public double F1Score { get; set; }
    public double AUC { get; set; }
}

public class DnsData
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

public class DnsPrediction
{
    [ColumnName("PredictedLabel")] public bool IsLegitimate { get; set; }
    public float Probability { get; set; }
    public float Score { get; set; }
    public string Verdict => IsLegitimate ? "Безопасный" : "Вредоносный";
}