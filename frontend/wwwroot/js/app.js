const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://127.0.0.1:5000/api/dns/check'
    : `http://${window.location.hostname}:5000/api/dns/check`;

const domainInput = document.getElementById('domainInput');
const checkBtn = document.getElementById('checkBtn');
const resultDiv = document.getElementById('result');
const resultHeader = document.getElementById('resultHeader');
const resultDetails = document.getElementById('resultDetails');
const errorDiv = document.getElementById('error');
const loadingDiv = document.getElementById('loading');

// Проверка домена
async function checkDomain(domain) {
    hideAll();

    if (!domain || domain.trim().length < 3) {
        showError('Введите корректное доменное имя (минимум 3 символа)');
        return;
    }

    showLoading();

    try {
        const response = await fetch(`${API_URL}?domain=${encodeURIComponent(domain.trim())}`);

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Ошибка сервера: ${response.status}`);
        }

        const data = await response.json();
        showResult(data);
    } catch (err) {
        showError(err.message || 'Не удалось подключиться к серверу');
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
        <span class="label">Домен:</span>
        <span class="value">${escapeHtml(data.domain)}</span>
        
        <span class="label">Статус:</span>
        <span class="value">${data.verdict}</span>
        
        <span class="label">Вероятность:</span>
        <span class="value">${probPercent}%</span>
        
        <span class="label">Проверено:</span>
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

// События
checkBtn.addEventListener('click', () => checkDomain(domainInput.value));

domainInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        checkDomain(domainInput.value);
    }
});

// Примеры
document.querySelectorAll('.example').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        domainInput.value = link.textContent;
        checkDomain(link.textContent);
    });
});