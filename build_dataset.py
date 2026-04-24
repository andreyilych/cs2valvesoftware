import csv
import math
import re
import random
import urllib.request
import zipfile
import io
import os
import ssl

# === ИСПРАВЛЕНИЕ 1: ОТКЛЮЧЕНИЕ ПРОВЕРКИ SSL ===
# Это решает ошибку CERTIFICATE_VERIFY_FAILED
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Для старых версий Python, где проверка не была обязательной
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# === ИСТОЧНИКИ ===
LEGIT_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
MAL_URLS = [
    "https://raw.githubusercontent.com/mitchellkrogza/phishing.database/master/phishing-domains-ACTIVE.txt",
    "https://urlhaus.abuse.ch/downloads/text_recent/"
]

def calc_entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((count/len(s)) * math.log2(count/len(s)) for count in freq.values())

def get_tld_risk(tld):
    high = {"xyz","pw","tk","ml","ga","cf","gq","top","work","click","link","biz","info","loan","cc","ws","buzz","club"}
    med = {"mobi","name","pro","eu","asia","site","online","store","tech"}
    t = tld.lower()
    return 1.0 if t in high else (0.5 if t in med else 0.0)

def extract_domain_parts(domain):
    domain = domain.strip().lower()
    parts = domain.split('.')
    if len(parts) < 2: return "", "", 0
    tld = parts[-1]
    name = parts[-2]
    subdomains = len(parts) - 2
    full_name = ".".join(parts[:-1]) if subdomains > 0 else name
    return full_name, tld, subdomains

def extract_features(domain, is_malicious):
    name, tld, sub_count = extract_domain_parts(domain)
    if not name or not tld: return None

    name_len = len(name)
    dot_count = domain.count('.')
    entropy = calc_entropy(domain)
    digits = sum(1 for c in name if c.isdigit())
    digit_ratio = digits / name_len if name_len > 0 else 0.0
    
    vowels = sum(1 for c in name.lower() if c in "aeiouyаеёиоуыэюя")
    consonants = max(0, name_len - vowels - digits)
    consonant_ratio = consonants / name_len if name_len > 0 else 0.0
    
    return {
        'Domain': domain,
        'NameLength': name_len,
        'DotCount': dot_count,
        'Entropy': round(entropy, 4),
        'DigitRatio': round(digit_ratio, 4),
        'ConsonantRatio': round(consonant_ratio, 4),
        'HasHyphen': 1.0 if '-' in name else 0.0,
        'TldRisk': get_tld_risk(tld),
        'SubdomainCount': sub_count,
        'TldLength': len(tld),
        'IsMalicious': is_malicious
    }

def download_text(url, timeout=20):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='ignore')

def download_zip(url, inner_filename, timeout=30):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        with zipfile.ZipFile(io.BytesIO(resp.read())) as z:
            return z.read(inner_filename).decode('utf-8')

def fetch_legit(limit=30000):
    print("⬇️ Попытка загрузки легитимных доменов (Umbrella)...")
    try:
        data = download_zip(LEGIT_URL, "top-1m.csv")
        # Парсинг формата: rank,domain
        domains = [line.split(',')[1].strip() for line in data.splitlines() if ',' in line]
        valid_domains = [d for d in domains if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', d)]
        print(f"✅ Загружено {len(valid_domains)} легитимных доменов.")
        return valid_domains[:limit]
    except Exception as e:
        print(f"⚠️ Ошибка загрузки: {e}")
        print("🔄 Генерируем запасные легитимные домены...")
        return generate_fallback_legit(limit)

def generate_fallback_legit(limit):
    """Генерирует правдоподобные легитимные домены, если интернет недоступен."""
    prefixes = ["tech", "cloud", "web", "app", "net", "soft", "global", "market", "store", "data", "sys", "pro", "lab", "dev", "hub", "box", "line", "node", "core", "base"]
    suffixes = ["group", "inc", "corp", "ltd", "com", "io", "net", "org", "co", "tech", "solutions", "services", "systems", "partners"]
    tlds = ["com", "org", "net", "ru", "de", "fr", "uk", "us", "ca"]
    
    domains = set()
    while len(domains) < limit:
        p = random.choice(prefixes)
        s = random.choice(suffixes)
        t = random.choice(tlds)
        # Комбинируем: tech-solutions.com, webapp.net и т.д.
        separator = random.choice(["-", "", ".", ""])
        name = f"{p}{separator}{s}"
        domains.add(f"{name}.{t}")
    return list(domains)

def fetch_malicious(limit=30000):
    print("⬇️ Загрузка вредоносных доменов...")
    domains = set()
    valid_re = re.compile(r'^[a-z0-9.-]+\.[a-z]{2,}$')
    for url in MAL_URLS:
        try:
            print(f"   -> {url}")
            text = download_text(url)
            for line in text.splitlines():
                # Очистка от мусора
                line = line.strip().split()[0].split('/')[2] if '/' in line else line.strip()
                if valid_re.match(line):
                    domains.add(line)
        except Exception as e:
            print(f"   ❌ Ошибка источника {url}: {e}")
            continue
    print(f"✅ Найдено {len(domains)} уникальных вредоносных доменов.")
    return list(domains)[:limit]

if __name__ == "__main__":
    print("🚀 Запуск сборки датасета...")
    legit = fetch_legit(30000)
    malicious = fetch_malicious(30000)
    
    print(f"📊 Итого: Легитимных={len(legit)}, Вредоносных={len(malicious)}")

    if not legit and not malicious:
        print("❌ ОШИБКА: Не удалось получить данные ни из одного источника.")
        exit(1)

    rows = []
    # Обработка легитимных
    for d in legit:
        f = extract_features(d, False)
        if f: rows.append(f)
    
    # Обработка вредоносных
    for d in malicious:
        f = extract_features(d, True)
        if f: rows.append(f)

    # === ИСПРАВЛЕНИЕ 2: ЗАЩИТА ОТ ПУСТОГО СПИСКА ===
    if not rows:
        print("❌ ОШИБКА: Список строк пуст после обработки.")
        exit(1)

    # Балансировка 50/50
    random.seed(42)
    legit_rows = [r for r in rows if not r['IsMalicious']]
    mal_rows = [r for r in rows if r['IsMalicious']]
    
    # Берем минимальное количество из двух классов
    n = min(len(legit_rows), len(mal_rows))
    if n == 0:
        print("⚠️ Предупреждение: Один из классов пуст. Балансировка невозможна.")
        balanced = rows
    else:
        balanced = random.sample(legit_rows, n) + random.sample(mal_rows, n)
    
    random.shuffle(balanced)

    out_file = "backend/legitphish.csv"
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    
    with open(out_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=balanced[0].keys())
        writer.writeheader()
        writer.writerows(balanced)
    
    print(f"💾 Успешно! Сохранено {len(balanced)} строк в {out_file}")