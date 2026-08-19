const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const BASE_URL = isLocal ? 'http://localhost:3000' : '';
const API_URL = `${BASE_URL}/api/scan-url`;
const FILE_API_URL = `${BASE_URL}/api/scan-file`;

// State management for history
let activityHistory = JSON.parse(localStorage.getItem('cypherx_history')) || [
    { date: new Date(Date.now() - 120000).toLocaleString([], {hour: '2-digit', minute:'2-digit'}), url: 'https://example.com', score: 12, status: 'SAFE', source: 'URL Scan' },
    { date: new Date(Date.now() - 480000).toLocaleString([], {hour: '2-digit', minute:'2-digit'}), url: 'payment-qr.png', score: 45, status: 'SUSPICIOUS', source: 'QR Inspection' },
    { date: new Date(Date.now() - 900000).toLocaleString([], {hour: '2-digit', minute:'2-digit'}), url: 'https://secure-login.xyz', score: 92, status: 'DANGEROUS', source: 'URL Scan' }
];
let totalScanned = parseInt(localStorage.getItem('cypherx_total')) || 2451;
let totalThreats = parseInt(localStorage.getItem('cypherx_threats')) || 142;

function saveHistory() {
    localStorage.setItem('cypherx_history', JSON.stringify(activityHistory));
    localStorage.setItem('cypherx_total', totalScanned);
    localStorage.setItem('cypherx_threats', totalThreats);
}

function addToHistory(url, score, status, source) {
    const entry = {
        date: new Date().toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
        url: url,
        score: score,
        status: status,
        source: source
    };
    activityHistory.unshift(entry);
    if(activityHistory.length > 50) activityHistory.pop();
    
    totalScanned++;
    if(status !== 'SAFE') totalThreats++;
    saveHistory();
    updateWidget(url, status);
    renderRecentActivity();
}

// Widget logic
const widget = document.getElementById('floating-widget');
const widgetPanel = document.getElementById('widget-panel');
const closeWidget = document.getElementById('close-widget');
const widgetUrl = document.getElementById('widget-last-url');

if(widget && widgetPanel) {
    widget.addEventListener('click', () => {
        widgetPanel.classList.toggle('show');
    });
    if (closeWidget) {
        closeWidget.addEventListener('click', () => {
            widgetPanel.classList.remove('show');
        });
    }
}

function updateWidget(url, status) {
    if(widgetUrl) {
        widgetUrl.textContent = `${url} (${status})`;
        let color = status === 'SAFE' ? 'var(--status-safe)' : (status === 'SUSPICIOUS' ? 'var(--status-warning)' : 'var(--status-danger)');
        widgetUrl.style.color = color;
    }
}

// Global initialization
document.addEventListener('DOMContentLoaded', () => {
    // Mobile menu toggle
    const mobileMenu = document.getElementById('mobile-menu');
    const navLinks = document.querySelector('.nav-links');

    if (mobileMenu && navLinks) {
        mobileMenu.addEventListener('click', () => {
            mobileMenu.classList.toggle('active');
            navLinks.classList.toggle('active');
        });
    }

    // Segmented Quick Scan Tabs Switcher
    const quickTabs = document.querySelectorAll('.quick-scan-tab');
    quickTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            quickTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const targetPaneId = tab.getAttribute('data-target');
            document.querySelectorAll('.tab-pane').forEach(pane => {
                pane.classList.remove('active');
            });
            const targetPane = document.getElementById(targetPaneId);
            if (targetPane) targetPane.classList.add('active');
        });
    });

    if(activityHistory.length > 0) {
        updateWidget(activityHistory[0].url, activityHistory[0].status);
    }
    
    renderRecentActivity();
    renderActivityTable(activityHistory);

    // Search filter for activity page
    const activitySearch = document.getElementById('activity-search');
    if (activitySearch) {
        activitySearch.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const filtered = activityHistory.filter(item => 
                item.url.toLowerCase().includes(query) || 
                item.status.toLowerCase().includes(query) ||
                item.source.toLowerCase().includes(query)
            );
            renderActivityTable(filtered);
        });
    }

    initThreatOverviewChart();
});

function renderRecentActivity() {
    const dl = document.getElementById('dashboard-scan-list');
    if(!dl) return;
    dl.innerHTML = '';
    
    activityHistory.slice(0, 4).forEach(item => {
        const li = document.createElement('li');
        li.className = 'scan-item';
        
        let isQr = item.source.toLowerCase().includes('qr');
        let isFile = item.source.toLowerCase().includes('file') || item.source.toLowerCase().includes('payload');
        let iconClass = isQr ? 'fa-qrcode' : (isFile ? 'fa-file-code' : 'fa-link');
        let badgeClass = item.status === 'SAFE' ? 'safe' : (item.status === 'SUSPICIOUS' ? 'suspicious' : 'dangerous');
        
        li.innerHTML = `
            <div class="scan-item-info">
                <div class="scan-item-icon"><i class="fas ${iconClass}"></i></div>
                <div>
                    <div class="scan-url" title="${item.url}">${item.url}</div>
                    <div class="scan-type">${item.source} • ${item.date}</div>
                </div>
            </div>
            <span class="scan-badge ${badgeClass}">${item.status}</span>
        `;
        dl.appendChild(li);
    });

    // Update Counters
    const scannedEl = document.getElementById('total-scanned');
    const threatsEl = document.getElementById('total-threats');
    const safeEl = document.getElementById('total-safe');
    const suspEl = document.getElementById('total-suspicious');

    if (scannedEl) scannedEl.textContent = totalScanned.toLocaleString();
    if (threatsEl) threatsEl.textContent = totalThreats.toLocaleString();
    if (safeEl) safeEl.textContent = Math.max(0, totalScanned - totalThreats).toLocaleString();
    if (suspEl) suspEl.textContent = Math.round(totalThreats * 0.4).toLocaleString();
}

function renderActivityTable(items) {
    const tb = document.getElementById('activity-table-body');
    if(!tb) return;
    tb.innerHTML = '';

    if (items.length === 0) {
        tb.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No scan records found.</td></tr>';
        return;
    }

    items.forEach(item => {
        const tr = document.createElement('tr');
        let tagClass = item.status === 'SAFE' ? 'safe' : (item.status === 'SUSPICIOUS' ? 'suspicious' : 'dangerous');
        
        tr.innerHTML = `
            <td style="color: var(--text-secondary);">${item.date}</td>
            <td style="font-weight: 500; word-break: break-all;">${item.url}</td>
            <td style="font-weight: 600;">${item.score}/100</td>
            <td><span class="scan-badge ${tagClass}">${item.status}</span></td>
            <td style="color: var(--text-secondary);">${item.source}</td>
        `;
        tb.appendChild(tr);
    });
}

function initThreatOverviewChart() {
    const ctx = document.getElementById('pieChart');
    if (!ctx || typeof Chart === 'undefined') return;

    new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Suspicious', 'Dangerous'],
            datasets: [{
                data: [2180, 129, 142],
                backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                borderColor: '#152033',
                borderWidth: 3,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#9ca3af',
                        font: { family: 'Inter', size: 12 },
                        padding: 16,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                }
            }
        }
    });
}

// URL Scanner API Wrap
async function fetchUrlSafety(url, source) {
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ url, source })
        });
        const data = await response.json();
        if (response.status === 429) {
            return { status: 'ERROR', reasons: [data.error?.message || 'Rate limit exceeded.'], riskScore: 0 };
        }
        if (response.status >= 400 && data.error) {
            return { status: 'ERROR', reasons: [data.error.message], riskScore: 0 };
        }
        const score = data.riskScore !== undefined ? data.riskScore : 0;
        addToHistory(url, score, data.status, source);
        return data;
    } catch(err) {
        return { status: 'ERROR', reasons: ['Failed to contact CypherX security scanner.'], riskScore: 0 };
    }
}

// Real Multipart File Scanner API Wrap
async function fetchFileSafety(file) {
    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch(FILE_API_URL, {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        
        if (response.status === 429) {
            return { status: 'ERROR', reasons: [data.error?.message || 'Rate limit exceeded.'], riskScore: 0 };
        }
        if (response.status >= 400 && data.error) {
            return { status: 'ERROR', reasons: [data.error.message], riskScore: 0 };
        }

        const score = data.riskScore !== undefined ? data.riskScore : 0;
        addToHistory(file.name, score, data.status, 'Payload Inspector');
        return data;
    } catch(err) {
        return { status: 'ERROR', reasons: ['Failed to upload and scan file payload.'], riskScore: 0 };
    }
}

// 1. Standard URL Scanner Handler
const urlScanForm = document.getElementById('url-scan-form');
if (urlScanForm) {
    urlScanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById('url-input').value.trim();
        if (!urlInput) return;

        const loader = document.getElementById('url-loader');
        const card = document.getElementById('url-result-card');
        
        if (card) card.style.display = 'none';
        if (loader) loader.style.display = 'block';

        const data = await fetchUrlSafety(urlInput, 'URL Scan');
        
        if (loader) loader.style.display = 'none';
        updateResultCard('url', data.status, data.reasons, data.riskScore, data.sha256);
        if (card) card.style.display = 'block';
    });
}

// 2. Quick Tab URL Scanner Handler
const quickUrlForm = document.getElementById('quick-url-form');
if (quickUrlForm) {
    quickUrlForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById('quick-url-input').value.trim();
        if (!urlInput) return;

        const loader = document.getElementById('quick-url-loader');
        const card = document.getElementById('quick-url-result-card');
        
        if (card) card.style.display = 'none';
        if (loader) loader.style.display = 'block';

        const data = await fetchUrlSafety(urlInput, 'Quick URL Scan');
        
        if (loader) loader.style.display = 'none';
        updateResultCard('quick-url', data.status, data.reasons, data.riskScore, data.sha256);
        if (card) card.style.display = 'block';
    });
}

// 3. Monitor Simulation
const mtForm = document.getElementById('monitor-form');
if(mtForm) {
    mtForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('monitor-input').value.trim();
        const loader = document.getElementById('monitor-loader');
        const modal = document.getElementById('monitor-intercept-modal');
        const backdrop = document.getElementById('monitor-modal-backdrop');
        
        if (loader) loader.style.display = 'block';
        mtForm.style.display = 'none';
        
        const data = await fetchUrlSafety(url, 'Live Monitor');
        
        setTimeout(() => {
            if (loader) loader.style.display = 'none';
            if(data.status !== 'SAFE' && data.riskScore > 30) {
                if (modal) modal.style.display = 'block';
                if (backdrop) backdrop.style.display = 'block';
                
                const scoreVal = document.getElementById('monitor-score-val');
                const statusVal = document.getElementById('monitor-status-val');
                const reasonVal = document.getElementById('monitor-reason-val');

                if (scoreVal) scoreVal.textContent = data.riskScore;
                if (statusVal) {
                    statusVal.textContent = data.status;
                    statusVal.className = data.status === 'DANGEROUS' ? 'scan-badge dangerous' : 'scan-badge suspicious';
                }
                if (reasonVal) reasonVal.textContent = Array.isArray(data.reasons) ? data.reasons.join(', ') : data.reasons;
                
                const btnBack = document.getElementById('btn-go-back');
                if (btnBack) {
                    btnBack.onclick = () => {
                        if (modal) modal.style.display = 'none';
                        if (backdrop) backdrop.style.display = 'none';
                        mtForm.style.display = 'block';
                        document.getElementById('monitor-input').value = '';
                    };
                }
                
                const btnProceed = document.getElementById('btn-proceed');
                if (btnProceed) {
                    btnProceed.onclick = () => {
                        window.open(url.startsWith('http') ? url : 'http://' + url, '_blank');
                        if (modal) modal.style.display = 'none';
                        if (backdrop) backdrop.style.display = 'none';
                        mtForm.style.display = 'block';
                    };
                }
            } else {
                mtForm.style.display = 'block';
                document.getElementById('monitor-input').value = '';
                alert(`CypherX Security: URL verified safe (Risk Score: ${data.riskScore}/100). Opening link.`);
                window.open(url.startsWith('http') ? url : 'http://' + url, '_blank');
            }
        }, 900);
    });
}

// 4. Real Multipart File Scanner Handler
const fileInput = document.getElementById('file-input');
const fileBtn = document.getElementById('scan-file-btn');

if(fileInput && fileBtn) {
    fileInput.addEventListener('change', function() {
        if(this.files.length > 0) {
            const fileNameEl = document.getElementById('selected-filename');
            if (fileNameEl) {
                fileNameEl.innerHTML = `<i class="fas fa-file"></i> Selected payload: <strong>${this.files[0].name}</strong> (${(this.files[0].size / 1024).toFixed(1)} KB)`;
            }
            fileBtn.style.display = 'inline-flex';
            const fileCard = document.getElementById('file-result-card');
            if (fileCard) fileCard.style.display = 'none';
        }
    });

    fileBtn.addEventListener('click', async () => {
        const file = fileInput.files[0];
        if(!file) return;

        fileBtn.style.display = 'none';
        const fileLoader = document.getElementById('file-loader');
        if (fileLoader) fileLoader.style.display = 'block';

        const data = await fetchFileSafety(file);
        
        if (fileLoader) fileLoader.style.display = 'none';
        updateResultCard('file', data.status, data.reasons, data.riskScore, data.sha256);
        const fileCard = document.getElementById('file-result-card');
        if (fileCard) fileCard.style.display = 'block';
    });
}

// 5. QR Scanner Logic
const qrInput = document.getElementById('qr-input');
const qrPreviewContainer = document.getElementById('preview-container');
const qrPreviewImg = document.getElementById('qr-preview');
const scanQrBtn = document.getElementById('scan-qr-btn');

if (qrInput) {
    qrInput.addEventListener('change', function() {
        if (this.files && this.files[0]) {
            const file = this.files[0];
            const reader = new FileReader();
            reader.onload = function(e) {
                if (qrPreviewImg) qrPreviewImg.src = e.target.result;
                if (qrPreviewContainer) qrPreviewContainer.style.display = 'block';
                if (scanQrBtn) scanQrBtn.style.display = 'inline-flex';
                const errEl = document.getElementById('qr-error-msg');
                const decodedEl = document.getElementById('qr-decoded-text');
                const resultCard = document.getElementById('qr-result-card');
                if (errEl) errEl.style.display = 'none';
                if (decodedEl) decodedEl.style.display = 'none';
                if (resultCard) resultCard.style.display = 'none';
            }
            reader.readAsDataURL(file);
        }
    });

    if (scanQrBtn) {
        scanQrBtn.addEventListener('click', async () => {
            const errEl = document.getElementById('qr-error-msg');
            const qrLoader = document.getElementById('qr-loader');
            const qrResultCard = document.getElementById('qr-result-card');
            const qrDecodedText = document.getElementById('qr-decoded-text');

            if (errEl) errEl.style.display = 'none';
            
            try {
                if (typeof ZXing === 'undefined') {
                    throw new Error("QR library unavailable");
                }
                const codeReader = new ZXing.BrowserQRCodeReader();
                const result = await codeReader.decodeFromImageElement(qrPreviewImg);
                const url = result.text;
                
                const extractedUrlEl = document.getElementById('extracted-url');
                if (extractedUrlEl) extractedUrlEl.textContent = url;
                if (qrDecodedText) qrDecodedText.style.display = 'block';

                if (qrLoader) qrLoader.style.display = 'block';
                if (qrResultCard) qrResultCard.style.display = 'none';
                
                const data = await fetchUrlSafety(url, 'QR Inspection');
                
                if (qrLoader) qrLoader.style.display = 'none';
                updateResultCard('qr', data.status, data.reasons, data.riskScore, data.sha256);
                if (qrResultCard) qrResultCard.style.display = 'block';
                
            } catch (err) {
                if (qrLoader) qrLoader.style.display = 'none';
                if (errEl) {
                    errEl.style.display = 'block';
                    errEl.className = 'recommendation-box';
                    errEl.style.borderColor = 'var(--status-danger-border)';
                    errEl.style.color = 'var(--status-danger)';
                    errEl.innerHTML = `<i class="fas fa-exclamation-circle"></i> Could not read a valid QR code in this image. Please try another image.`;
                }
            }
        });
    }
}

/**
 * Modern Security Result Card Updater
 */
function updateResultCard(prefix, status, reasons, score, sha256) {
    const card = document.getElementById(`${prefix}-result-card`);
    if (!card) return;

    let reasonsArray = Array.isArray(reasons) ? reasons : [reasons];
    card.className = `result-card ${status.toLowerCase()}`;

    let iconClass = status === 'SAFE' ? 'fa-circle-check' : (status === 'SUSPICIOUS' ? 'fa-triangle-exclamation' : 'fa-circle-xmark');
    let statusTitle = status === 'SAFE' ? 'SAFE' : (status === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'DANGEROUS');
    
    let recommendationText = status === 'SAFE' 
        ? 'This URL or file passed security checks. No obvious threat indicators were found.'
        : (status === 'SUSPICIOUS'
            ? 'Proceed with caution. CypherX identified suspicious keywords or unusual domain patterns.'
            : 'Do not open this link or file. It matches known phishing blacklists or malicious software patterns.');

    let shaHtml = sha256 ? `<div style="font-family: var(--font-mono); font-size: 0.775rem; color: var(--text-secondary); margin-bottom: 10px;">SHA-256: ${sha256}</div>` : '';

    card.innerHTML = `
        <div class="result-header">
            <div class="result-status-wrap">
                <i class="fas ${iconClass} result-icon"></i>
                <div>
                    <div class="result-status-title">${statusTitle}</div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary);">Security Analysis Result</div>
                </div>
            </div>
            <div class="risk-score-pill">Risk Score: ${score} / 100</div>
        </div>

        ${shaHtml}

        <div class="result-body">
            <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-heading); margin-bottom: 6px;">${status === 'SAFE' ? 'Security Analysis Findings:' : 'Why CypherX flagged this:'}</div>
            <ul class="result-reason-list">
                ${reasonsArray.map(reason => `
                    <li class="result-reason-item">
                        <i class="fas ${status === 'SAFE' ? 'fa-check safe-text' : 'fa-exclamation warning-text'}"></i>
                        <span>${reason}</span>
                    </li>
                `).join('')}
            </ul>
        </div>

        <div class="recommendation-box">
            <i class="fas fa-circle-info" style="color: var(--accent-blue);"></i>
            <div>
                <strong style="color: var(--text-heading);">Recommendation:</strong>
                <div style="color: var(--text-secondary); margin-top: 2px;">${recommendationText}</div>
            </div>
        </div>
    `;
}
