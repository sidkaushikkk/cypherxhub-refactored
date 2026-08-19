const { URL } = require('url');

const DISALLOWED_PROTOCOLS = ['javascript:', 'file:', 'data:', 'ftp:', 'vbscript:', 'blob:'];
const SUSPICIOUS_TLDS = ['.ru', '.tk', '.ml', '.xyz', '.click', '.top', '.gq', '.work', '.info', '.fit', '.cf', '.ga'];

// Redirect & callback query parameter keys commonly abused in open redirect attacks
const REDIRECT_PARAM_KEYS = [
    'redirect', 'redirect_to', 'redirect_url', 'url', 'dest', 'destination', 
    'next', 'return', 'return_url', 'target', 'goto', 'callback', 'r', 'link'
];

/**
 * Validate and normalize input URL into detailed structured components
 */
function validateAndNormalizeUrl(rawInput) {
    if (!rawInput || typeof rawInput !== 'string') {
        throw { code: 'INVALID_INPUT', message: 'URL must be a non-empty string.', status: 400 };
    }

    let trimmed = rawInput.trim();
    if (trimmed.length > 2048) {
        throw { code: 'URL_TOO_LONG', message: 'URL exceeds maximum allowed length of 2048 characters.', status: 400 };
    }

    // Check for explicit disallowed protocols before adding default scheme
    const lowerInput = trimmed.toLowerCase();
    for (const proto of DISALLOWED_PROTOCOLS) {
        if (lowerInput.startsWith(proto)) {
            throw { code: 'UNSUPPORTED_PROTOCOL', message: `Unsupported or unsafe protocol (${proto}). Only HTTP and HTTPS URLs are allowed.`, status: 400 };
        }
    }

    // Add protocol if missing
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
        trimmed = 'http://' + trimmed;
    }

    try {
        const parsed = new URL(trimmed);
        
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            throw { code: 'UNSUPPORTED_PROTOCOL', message: `Protocol ${parsed.protocol} is not supported. Only HTTP and HTTPS URLs are allowed.`, status: 400 };
        }

        if (!parsed.hostname) {
            throw { code: 'INVALID_HOSTNAME', message: 'URL lacks a valid hostname.', status: 400 };
        }

        const normalizedHost = parsed.hostname.toLowerCase();
        
        return {
            rawUrl: rawInput,
            normalizedUrl: parsed.toString(),
            protocol: parsed.protocol,
            hostname: normalizedHost,
            port: parsed.port,
            pathname: parsed.pathname,
            search: parsed.search,
            hash: parsed.hash,
            username: parsed.username,
            password: parsed.password,
            searchParams: parsed.searchParams
        };
    } catch (err) {
        if (err.code && err.status) throw err;
        throw { code: 'INVALID_URL_SYNTAX', message: 'Malformed URL syntax. Could not parse valid host and protocol.', status: 400 };
    }
}

/**
 * Check if hostname is a raw IP address (v4 or v6)
 */
function isIpAddress(hostname) {
    if (!hostname) return false;
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const ipv6Regex = /^\[?[a-fA-F0-9:]+\]?$/;
    return ipv4Regex.test(hostname) || (hostname.includes(':') && ipv6Regex.test(hostname));
}

/**
 * Check for suspicious TLDs
 */
function getSuspiciousTld(hostname) {
    if (!hostname) return null;
    for (const ext of SUSPICIOUS_TLDS) {
        if (hostname.endsWith(ext)) {
            return ext;
        }
    }
    return null;
}

/**
 * Detect confusing Unicode or mixed-script homograph characters in hostname
 */
function detectHomographUnicode(hostname) {
    if (!hostname) return null;

    // Check for Punycode prefix xn--
    if (hostname.includes('xn--')) {
        return {
            isPunycode: true,
            hasHomograph: false,
            message: 'Domain uses Punycode/Internationalized Domain Name (IDN) encoding (xn--).'
        };
    }

    // Check for non-ASCII characters
    const nonAsciiRegex = /[^\u0000-\u007F]/;
    if (nonAsciiRegex.test(hostname)) {
        // Cyrillic homographs that visually mimic Latin characters (e.g., а, е, о, р, с, х)
        const cyrillicHomographRegex = /[\u0430\u0435\u043E\u0440\u0441\u0445\u0410\u0415\u041E\u0420\u0421\u0425]/;
        const hasCyrillicLookalikes = cyrillicHomographRegex.test(hostname);

        return {
            isPunycode: false,
            hasHomograph: hasCyrillicLookalikes,
            message: hasCyrillicLookalikes
                ? 'Potentially confusing Unicode homograph characters (Cyrillic lookalikes) detected in hostname.'
                : 'Hostname contains non-ASCII Unicode characters.'
        };
    }

    return null;
}

/**
 * Analyze query parameters for redirect targets or embedded URLs
 */
function analyzeQueryParameters(searchParams) {
    if (!searchParams) return null;

    let redirectFound = null;

    for (const [key, value] of searchParams.entries()) {
        const lowerKey = key.toLowerCase();
        const lowerVal = value.toLowerCase();

        const isRedirectKey = REDIRECT_PARAM_KEYS.includes(lowerKey);
        const containsUrlValue = lowerVal.includes('http://') || 
                                lowerVal.includes('https://') || 
                                lowerVal.includes('http%3a%2f%2f') || 
                                lowerVal.includes('https%3a%2f%2f');

        if (isRedirectKey || containsUrlValue) {
            redirectFound = {
                paramKey: key,
                paramValue: value,
                isUrlValue: containsUrlValue,
                message: `Query parameter '${key}' contains an embedded target URL or redirect parameter.`
            };
            break;
        }
    }

    return redirectFound;
}

/**
 * Count percent-encoding sequences (%XX) in path or search
 */
function countPercentEncodings(str) {
    if (!str) return 0;
    const matches = str.match(/%[0-9a-fA-F]{2}/g);
    return matches ? matches.length : 0;
}

module.exports = {
    validateAndNormalizeUrl,
    isIpAddress,
    getSuspiciousTld,
    detectHomographUnicode,
    analyzeQueryParameters,
    countPercentEncodings,
    SUSPICIOUS_TLDS,
    REDIRECT_PARAM_KEYS
};
