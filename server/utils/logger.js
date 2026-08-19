const config = require('../config/env');

/**
 * Sanitize log strings to prevent leaking sensitive API keys or credentials
 */
function sanitize(msg) {
    if (typeof msg !== 'string') return msg;
    let sanitized = msg;
    if (config.googleSafeBrowsingApiKey) {
        sanitized = sanitized.replace(new RegExp(config.googleSafeBrowsingApiKey, 'g'), '[REDACTED_API_KEY]');
    }
    // Redact password or key query parameters if present
    sanitized = sanitized.replace(/(password|passwd|secret|api_key|token|access_token)=[^&]+/gi, '$1=[REDACTED]');
    return sanitized;
}

const logger = {
    info: (message, meta = {}) => {
        console.log(`[INFO] ${new Date().toISOString()} - ${sanitize(message)}`, Object.keys(meta).length ? meta : '');
    },
    warn: (message, meta = {}) => {
        console.warn(`[WARN] ${new Date().toISOString()} - ${sanitize(message)}`, Object.keys(meta).length ? meta : '');
    },
    error: (message, meta = {}) => {
        console.error(`[ERROR] ${new Date().toISOString()} - ${sanitize(message)}`, Object.keys(meta).length ? meta : '');
    },
    http: (requestId, method, path, statusCode, durationMs) => {
        console.log(`[HTTP] ${new Date().toISOString()} | reqId=${requestId} | ${method} ${path} | status=${statusCode} | duration=${durationMs}ms`);
    },
    scan: (scanId, scanType, target, status, riskScore, durationMs) => {
        console.log(`[SCAN] ${new Date().toISOString()} | id=${scanId} | type=${scanType} | target=${sanitize(target)} | status=${status} | score=${riskScore} | duration=${durationMs}ms`);
    }
};

module.exports = logger;
