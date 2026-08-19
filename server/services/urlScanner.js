const fs = require('fs');
const path = require('path');
const { 
    validateAndNormalizeUrl, 
    isIpAddress, 
    getSuspiciousTld, 
    detectHomographUnicode, 
    analyzeQueryParameters, 
    countPercentEncodings 
} = require('../utils/url');
const { analyzeTyposquatting, isOfficialBrandDomain } = require('../utils/typosquatting');
const { checkGoogleSafeBrowsing } = require('./safeBrowsing');
const { INDICATOR_DEFINITIONS } = require('../engine/indicators');
const { evaluateRisk } = require('../engine/riskEngine');
const logger = require('../utils/logger');

// Load phishing domain blacklist database
let phishingDb = [];
try {
    const dbPath = path.join(__dirname, '../data/phishing-db.json');
    const fallbackPath = path.join(__dirname, '../../phishing-db.json');
    const actualPath = fs.existsSync(dbPath) ? dbPath : fallbackPath;
    
    if (fs.existsSync(actualPath)) {
        const data = fs.readFileSync(actualPath, 'utf8');
        phishingDb = JSON.parse(data);
    } else {
        phishingDb = require('../../phishing-db.json');
    }
    logger.info(`Loaded ${phishingDb.length} phishing domain entries into URL Scanner.`);
} catch (err) {
    try {
        phishingDb = require('../../phishing-db.json');
        logger.info(`Loaded ${phishingDb.length} phishing domain entries via fallback.`);
    } catch (fallbackErr) {
        logger.error('Failed to load phishing-db.json', { error: err.message });
    }
}

const KEYWORDS = [
    'login', 'verify', 'secure', 'update', 'bank', 'account', 'signin', 'confirm', 
    'password', 'payment', 'alert', 'suspended', 'reset', 'free', 'gift', 'bonus', 
    'crypto', 'win', 'lottery', 'refund', 'kyc', 'wallet', 'upi'
];

/**
 * Perform multi-layered URL threat intelligence inspection
 * 
 * @param {string} rawUrl Input URL string
 * @param {string} source Source identifier (e.g. 'URL Scanner', 'QR Inspector')
 * @returns {Promise<Object>} Unified risk verdict
 */
async function scanUrl(rawUrl, source = 'URL Scanner') {
    const startTime = Date.now();

    // Layer 1: Normalization & Scheme Validation
    const urlData = validateAndNormalizeUrl(rawUrl);
    const { normalizedUrl, protocol, hostname, port, pathname, search, username, searchParams } = urlData;

    let indicators = [];

    // Layer 2: Protocol Security Analysis
    if (protocol === 'http:') {
        indicators.push(INDICATOR_DEFINITIONS.HTTP_NO_TLS);
    }

    // Layer 3: Authority & Userinfo Deception (@ trick)
    if (username) {
        indicators.push({
            ...INDICATOR_DEFINITIONS.URL_USERINFO_DECEPTION,
            message: `URL uses misleading authority userinfo syntax (@ trick). Visual brand '${username}' is a username; actual destination host is '${hostname}'.`
        });
    }

    // Layer 4: Hostname & IP Analysis
    const isIpHost = isIpAddress(hostname);
    const isOfficialBrand = isOfficialBrandDomain(hostname);

    if (isIpHost) {
        indicators.push({
            ...INDICATOR_DEFINITIONS.IP_ADDRESS_HOSTNAME,
            message: `URL host '${hostname}' is a raw IP address instead of a registered domain name.`
        });
    } else {
        // Domain-specific heuristic checks (only applied to standard domain hostnames)
        if (hostname.length > 40) {
            indicators.push(INDICATOR_DEFINITIONS.LONG_HOSTNAME);
        }

        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount >= 3) {
            indicators.push(INDICATOR_DEFINITIONS.EXCESSIVE_HYPHENS);
        }

        // Layer 5: Subdomain & TLD Analysis
        const suspiciousTld = getSuspiciousTld(hostname);
        if (suspiciousTld) {
            indicators.push({
                ...INDICATOR_DEFINITIONS.SUSPICIOUS_TLD,
                message: `Domain uses an uncommon top-level domain (${suspiciousTld}) frequently associated with phishing.`
            });
        }

        const subdomainParts = hostname.split('.');
        if (subdomainParts.length >= 4) {
            indicators.push(INDICATOR_DEFINITIONS.EXCESSIVE_SUBDOMAINS);
        }

        // Layer 6: Punycode & Homograph Unicode Analysis
        const homographAnalysis = detectHomographUnicode(hostname);
        if (homographAnalysis) {
            if (homographAnalysis.isPunycode) {
                indicators.push(INDICATOR_DEFINITIONS.PUNYCODE_DOMAIN);
            }
            if (homographAnalysis.hasHomograph) {
                indicators.push(INDICATOR_DEFINITIONS.HOMOGRAPH_UNICODE_CHARACTERS);
            }
        }

        // Layer 7: Typosquatting & Brand Similarity Analysis
        const typosquatResult = analyzeTyposquatting(hostname);
        if (typosquatResult) {
            indicators.push({
                ...INDICATOR_DEFINITIONS.TYPOSQUATTING_BRAND_IMPERSONATION,
                message: typosquatResult.message
            });
        }
    }

    // Layer 8: Path, Query Obfuscation & Redirect Analysis
    if (port && !['80', '443'].includes(port)) {
        indicators.push({
            ...INDICATOR_DEFINITIONS.SUSPICIOUS_NON_STANDARD_PORT,
            message: `URL uses non-standard web port (${port}).`
        });
    }

    const redirectAnalysis = analyzeQueryParameters(searchParams);
    if (redirectAnalysis) {
        indicators.push({
            ...INDICATOR_DEFINITIONS.SUSPICIOUS_REDIRECT_PARAMETER,
            message: redirectAnalysis.message
        });
    }

    const percentEncodingCount = countPercentEncodings(pathname + search);
    if (percentEncodingCount >= 3) {
        indicators.push(INDICATOR_DEFINITIONS.EXCESSIVE_PERCENT_ENCODING);
    }

    // Suspicious Security Keywords (skip path keyword alerts on official brand websites)
    if (!isOfficialBrand) {
        const fullPathStr = (hostname + pathname + search).toLowerCase();
        const foundKeywords = KEYWORDS.filter(kw => fullPathStr.includes(kw));
        if (foundKeywords.length > 0) {
            indicators.push({
                ...INDICATOR_DEFINITIONS.SUSPICIOUS_KEYWORD_MATCH,
                message: `URL path contains security-sensitive keywords: ${foundKeywords.slice(0, 4).join(', ')}.`
            });
        }
    }

    if (normalizedUrl.length > 75) {
        indicators.push(INDICATOR_DEFINITIONS.LONG_URL_LENGTH);
    }

    // Layer 9: External Threat Intelligence & Reputation Check
    // 9a. Local Threat Blacklist Database
    for (const blacklisted of phishingDb) {
        const lowerBlacklisted = blacklisted.toLowerCase();
        if (hostname === lowerBlacklisted || hostname.endsWith('.' + lowerBlacklisted)) {
            indicators.push({
                ...INDICATOR_DEFINITIONS.KNOWN_BLACK_LIST_DOMAIN,
                message: `Domain matches known phishing threat blacklist (${blacklisted}).`
            });
            break;
        }
    }

    // 9b. Google Safe Browsing API check
    const safeBrowsingIntel = await checkGoogleSafeBrowsing(normalizedUrl);
    if (safeBrowsingIntel.status === 'MALICIOUS') {
        indicators.push(INDICATOR_DEFINITIONS.GOOGLE_SAFE_BROWSING_MALICIOUS);
    }

    const threatIntelSummary = {
        googleSafeBrowsing: safeBrowsingIntel
    };

    const targetContext = {
        type: 'URL',
        value: normalizedUrl,
        rawUrl,
        scanType: source.toLowerCase().includes('qr') ? 'QR' : 'URL'
    };

    const verdict = evaluateRisk(indicators, threatIntelSummary, targetContext);
    verdict.normalizedUrl = normalizedUrl;
    verdict.source = source;

    const duration = Date.now() - startTime;
    logger.scan(Date.now().toString(36), verdict.scanType, normalizedUrl, verdict.status, verdict.riskScore, duration);

    return verdict;
}

module.exports = {
    scanUrl
};
