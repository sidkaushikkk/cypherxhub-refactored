/**
 * CypherX Evaluation Dataset Normalization & Validation Module
 */

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const VALID_LABELS = new Set(['BENIGN', 'MALICIOUS']);

/**
 * Normalize and validate a URL for dataset ingestion
 * 
 * @param {string} rawUrl 
 * @returns {Object} { rawUrl, normalizedUrl, isValid, error }
 */
function normalizeUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') {
        return {
            rawUrl: rawUrl || '',
            normalizedUrl: null,
            isValid: false,
            error: 'EMPTY_OR_NON_STRING_URL'
        };
    }

    let trimmed = rawUrl.trim();
    if (trimmed.length === 0) {
        return {
            rawUrl,
            normalizedUrl: null,
            isValid: false,
            error: 'EMPTY_URL'
        };
    }

    // Reject dangerous/unsupported non-web schemes
    const lowerPrefix = trimmed.toLowerCase();
    if (lowerPrefix.startsWith('javascript:') || 
        lowerPrefix.startsWith('file:') || 
        lowerPrefix.startsWith('data:') || 
        lowerPrefix.startsWith('ftp:') ||
        lowerPrefix.startsWith('mailto:') ||
        lowerPrefix.startsWith('tel:') ||
        lowerPrefix.startsWith('blob:')) {
        return {
            rawUrl,
            normalizedUrl: null,
            isValid: false,
            error: `UNSUPPORTED_SCHEME: ${lowerPrefix.split(':')[0]}`
        };
    }

    // Default to https:// if protocol is omitted
    let urlToParse = trimmed;
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
        urlToParse = `https://${trimmed}`;
    }

    try {
        const parsed = new URL(urlToParse);

        if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
            return {
                rawUrl,
                normalizedUrl: null,
                isValid: false,
                error: `DISALLOWED_PROTOCOL: ${parsed.protocol}`
            };
        }

        if (!parsed.hostname || parsed.hostname.length === 0) {
            return {
                rawUrl,
                normalizedUrl: null,
                isValid: false,
                error: 'MISSING_HOSTNAME'
            };
        }

        // Hostname and protocol to lowercase, strip fragment (#hash)
        parsed.hostname = parsed.hostname.toLowerCase();
        parsed.protocol = parsed.protocol.toLowerCase();
        parsed.hash = '';

        const normalizedUrl = parsed.toString();

        return {
            rawUrl,
            normalizedUrl,
            isValid: true,
            error: null
        };
    } catch (err) {
        return {
            rawUrl,
            normalizedUrl: null,
            isValid: false,
            error: `INVALID_URL_SYNTAX: ${err.message}`
        };
    }
}

/**
 * Validate and format an ingested dataset record
 * 
 * @param {Object} rawRecord 
 * @returns {Object} { isValid, record, error }
 */
function validateRecord(rawRecord) {
    if (!rawRecord || typeof rawRecord !== 'object') {
        return { isValid: false, record: null, error: 'RECORD_NOT_AN_OBJECT' };
    }

    const rawUrl = rawRecord.rawUrl || rawRecord.url;
    const normResult = normalizeUrl(rawUrl);

    if (!normResult.isValid) {
        return { isValid: false, record: null, error: normResult.error };
    }

    const label = rawRecord.label ? String(rawRecord.label).trim().toUpperCase() : null;
    if (!VALID_LABELS.has(label)) {
        return { isValid: false, record: null, error: `INVALID_GROUND_TRUTH_LABEL: ${rawRecord.label}` };
    }

    const record = {
        rawUrl: normResult.rawUrl,
        url: normResult.normalizedUrl,
        label: label,
        category: rawRecord.category || (label === 'BENIGN' ? 'normal_website' : 'phishing'),
        source: rawRecord.source || 'unknown',
        sourceId: rawRecord.sourceId !== undefined ? String(rawRecord.sourceId) : null,
        collectedAt: rawRecord.collectedAt || null,
        verifiedAt: rawRecord.verifiedAt || null
    };

    return {
        isValid: true,
        record,
        error: null
    };
}

module.exports = {
    normalizeUrl,
    validateRecord
};
