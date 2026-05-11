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
using System.Text.RegularExpressions;

namespace Backend;

public static class DnsFeatureExtractor
{
    private static readonly HashSet<string> PopularTlds = new()
    {
        ".com", ".org", ".net",
        ".ai",

        ".ru", /*".su",*/ ".рф",    // Russia
        ".by",                      // Belarus
        ".kz",                      // Kazakhstan

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

    private static readonly HashSet<string> RareBigrams = new()
    {
        "zx", "zq", "qx", "qj", "jk", "kj", "xv", "vx", "wp", "pw",
        "qz", "jq", "qk", "wq", "jz", "zj", "xk", "kx"
    };

    private static readonly HashSet<string> PopularBrands = new()
    {
        "google", "facebook", "youtube", "yahoo", "amazon", "microsoft", "apple",
        "netflix", "twitter", "instagram", "linkedin", "whatsapp", "snapchat",
        "paypal", "ebay", "aliexpress", "walmart", "reddit", "twitch",

        "yandex", /*"odnoklassniki",*/ "rambler", "avito", "wildberries",
        "sberbank", "tinkoff", "tbank", "alfabank", "gazprombank", "rostelecom",
        "kaspersky", "rutube", "kinopoisk", "lamoda", "samokat",
        "deliveryclub", "prodoctorov", "gosuslugi",

        "oreluniver", "orel-univ"

    };

    public static DnsData ExtractFeatures(string domain)
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

        return new DnsData
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

    public static string? ExtractDomain(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;

        var clean = Regex.Replace(input.Trim().ToLower(), @"^(https?://)?(www\.)?", "");
        clean = clean.Split('/', '?', ':')[0];

        return clean.Contains('.') && !System.Net.IPAddress.TryParse(clean, out _) ? clean : null;
    }

    private static float CalculateEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        var length = s.Length;
        return (float)s.GroupBy(c => c)
            .Select(g => (float)g.Count() / length)
            .Sum(p => -p * Math.Log2(p));
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
}