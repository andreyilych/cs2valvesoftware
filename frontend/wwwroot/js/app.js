const BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://127.0.0.1:5000'
    : `http://${window.location.hostname}:5000`;

const API_URL = `${BASE_URL}/api/dns/check`;
const METRICS_URL = `${BASE_URL}/api/dns/metrics`;

const domainInput = document.getElementById('domainInput');
const checkBtn = document.getElementById('checkBtn');
const resultDiv = document.getElementById('result');
const resultHeader = document.getElementById('resultHeader');
const resultDetails = document.getElementById('resultDetails');
const errorDiv = document.getElementById('error');
const loadingDiv = document.getElementById('loading');

const metricAccuracy = document.getElementById('metricAccuracy');
const metricPrecision = document.getElementById('metricPrecision');
const metricF1 = document.getElementById('metricF1');
const metricAuc = document.getElementById('metricAuc');

let lastCheckedDomain = '';

function showFieldError(msg) {
    const old = document.getElementById('fieldError');
    if (old) old.remove();
    
    const error = document.createElement('div');
    error.id = 'fieldError';
    error.className = 'field-error';
    error.textContent = msg;
    domainInput.parentNode.insertBefore(error, domainInput.nextSibling);
    domainInput.classList.add('input-error');
}

function clearFieldError() {
    const error = document.getElementById('fieldError');
    if (error) error.remove();
    domainInput.classList.remove('input-error');
}

async function loadMetrics() {
    try {
        const response = await fetch(METRICS_URL);
        if (!response.ok) return;
        const data = await response.json();
        showMetrics(data);
    } catch (err) {
        // метрики не грузятся — ничего не делаем
    }
}

function showMetrics(data) {
    metricAccuracy.textContent = (data.accuracy * 100).toFixed(1) + '%';
    metricPrecision.textContent = (data.precision * 100).toFixed(1) + '%';
    metricF1.textContent = (data.f1Score * 100).toFixed(1) + '%';
    metricAuc.textContent = (data.auc * 100).toFixed(1) + '%';
}

async function checkDomain(domain) {
    hideAll();
    clearFieldError();

    if (!domain || domain.trim() === '') {
        showFieldError('ВВЕДИТЕ ЦЕЛЬ');
        return;
    }

    let cleanDomain = domain.trim().toLowerCase();

    if (cleanDomain.startsWith('http://') || cleanDomain.startsWith('https://')) {
        cleanDomain = cleanDomain.replace(/^https?:\/\//, '');
    }

    if (cleanDomain.includes('/')) {
        cleanDomain = cleanDomain.split('/')[0];
    }

    if (cleanDomain.includes(':')) {
        cleanDomain = cleanDomain.split(':')[0];
    }

    if (/\s/.test(cleanDomain)) {
        showFieldError('ЦЕЛЬ НЕ ДОЛЖНА СОДЕРЖАТЬ ПРОБЕЛОВ');
        return;
    }

    const domainRegex = /^(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(cleanDomain)) {
        showFieldError('НЕКОРРЕКТНЫЙ ФОРМАТ ЦЕЛИ (пример: google.com)');
        return;
    }

    if (cleanDomain.length > 253) {
        showFieldError('ЦЕЛЬ СЛИШКОМ ДЛИННАЯ (максимум 253 символа)');
        return;
    }

    // if (cleanDomain === lastCheckedDomain) {
    //     showFieldError('ЦЕЛЬ УЖЕ ПРОВЕРЕНА. ВВЕДИТЕ НОВУЮ');
    //     return;
    // }

    lastCheckedDomain = cleanDomain;

    showLoading();

    try {
        const response = await fetch(`${API_URL}?domain=${encodeURIComponent(cleanDomain)}`);

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `ОШИБКА СЕРВЕРА: ${response.status}`);
        }

        const data = await response.json();
        loadingDiv.classList.add('hidden');
        showResult(data);
        loadMetrics();
    } catch (err) {
        loadingDiv.classList.add('hidden');
        showError(err.message || 'НЕ УДАЛОСЬ ПОДКЛЮЧИТЬСЯ К СЕРВЕРУ');
    }
}

function showResult(data) {
    const isSafe = data.isLegitimate;

    resultDiv.className = isSafe ? 'safe' : 'suspicious';
    resultHeader.textContent = isSafe
        ? `✅ ${data.verdict}`
        : `⚠ ${data.verdict}`;

    const probPercent = (data.probability * 100).toFixed(1);

    resultDetails.innerHTML = `
        <span class="label">ЦЕЛЬ:</span>
        <span class="value">${escapeHtml(data.domain)}</span>
        
        <span class="label">СТАТУС:</span>
        <span class="value">${data.verdict}</span>
        
        <span class="label">ВЕРОЯТНОСТЬ:</span>
        <span class="value">${probPercent}%</span>
        
        <span class="label">ПРОВЕРЕНО:</span>
        <span class="value">${new Date(data.checkedAt).toLocaleString('ru')}</span>
    `;

    resultDiv.classList.remove('hidden');
}

function showError(msg) {
    errorDiv.textContent = `❌ ${msg}`;
    errorDiv.classList.remove('hidden');
}

function showLoading() {
    loadingDiv.classList.remove('hidden');
}

function hideAll() {
    resultDiv.classList.add('hidden');
    errorDiv.classList.add('hidden');
    loadingDiv.classList.add('hidden');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

checkBtn.addEventListener('click', () => checkDomain(domainInput.value));

domainInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        checkDomain(domainInput.value);
    }
});

domainInput.addEventListener('input', function() {
    clearFieldError();
    lastCheckedDomain = '';
});

document.querySelectorAll('.example').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        domainInput.value = link.textContent;
        checkDomain(link.textContent);
    });
});

loadMetrics();