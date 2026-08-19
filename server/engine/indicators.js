/**
 * Indicator Severity Taxonomy
 */
const SEVERITY = {
    CRITICAL: 'CRITICAL',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
    INFO: 'INFO'
};

/**
 * Structured Threat Indicator Definitions & Baseline Scoring Weights
 */
const INDICATOR_DEFINITIONS = {
    // 1. Reputation & Known Threat Intelligence
    KNOWN_BLACK_LIST_DOMAIN: {
        type: 'KNOWN_BLACK_LIST_DOMAIN',
        severity: SEVERITY.CRITICAL,
        score: 100,
        message: 'Domain matches known phishing or malware threat blacklist.'
    },
    GOOGLE_SAFE_BROWSING_MALICIOUS: {
        type: 'GOOGLE_SAFE_BROWSING_MALICIOUS',
        severity: SEVERITY.CRITICAL,
        score: 80,
        message: 'URL flagged as malicious by Google Safe Browsing intelligence database.'
    },

    // 2. Domain & Hostname Analysis
    IP_ADDRESS_HOSTNAME: {
        type: 'IP_ADDRESS_HOSTNAME',
        severity: SEVERITY.HIGH,
        score: 40,
        message: 'URL uses a raw IP address host instead of a registered domain name.'
    },
    TYPOSQUATTING_BRAND_IMPERSONATION: {
        type: 'TYPOSQUATTING_BRAND_IMPERSONATION',
        severity: SEVERITY.HIGH,
        score: 45,
        message: 'Domain closely resembles a protected brand name (typosquatting / impersonation).'
    },
    SUSPICIOUS_TLD: {
        type: 'SUSPICIOUS_TLD',
        severity: SEVERITY.MEDIUM,
        score: 30,
        message: 'Domain uses an uncommon top-level domain frequently associated with abuse.'
    },
    PUNYCODE_DOMAIN: {
        type: 'PUNYCODE_DOMAIN',
        severity: SEVERITY.MEDIUM,
        score: 20,
        message: 'Domain uses Punycode / Internationalized Domain Names (xn--).'
    },
    HOMOGRAPH_UNICODE_CHARACTERS: {
        type: 'HOMOGRAPH_UNICODE_CHARACTERS',
        severity: SEVERITY.MEDIUM,
        score: 25,
        message: 'Potentially confusing Unicode or mixed-script homograph characters detected in hostname.'
    },
    EXCESSIVE_HYPHENS: {
        type: 'EXCESSIVE_HYPHENS',
        severity: SEVERITY.MEDIUM,
        score: 15,
        message: 'Unusually high number of hyphens in domain name (3 or more).'
    },
    EXCESSIVE_SUBDOMAINS: {
        type: 'EXCESSIVE_SUBDOMAINS',
        severity: SEVERITY.MEDIUM,
        score: 20,
        message: 'Domain contains excessive subdomain nesting depth.'
    },
    LONG_HOSTNAME: {
        type: 'LONG_HOSTNAME',
        severity: SEVERITY.LOW,
        score: 10,
        message: 'Domain hostname length is suspiciously long (>40 characters).'
    },

    // 3. URL Construction, Obfuscation & Redirects
    URL_USERINFO_DECEPTION: {
        type: 'URL_USERINFO_DECEPTION',
        severity: SEVERITY.HIGH,
        score: 65,
        message: 'URL uses userinfo authority syntax (@ trick) to visually disguise destination host.'
    },
    SUSPICIOUS_REDIRECT_PARAMETER: {
        type: 'SUSPICIOUS_REDIRECT_PARAMETER',
        severity: SEVERITY.MEDIUM,
        score: 30,
        message: 'URL query parameters contain embedded target URLs or redirect parameters.'
    },
    SUSPICIOUS_NON_STANDARD_PORT: {
        type: 'SUSPICIOUS_NON_STANDARD_PORT',
        severity: SEVERITY.MEDIUM,
        score: 25,
        message: 'URL uses a non-standard port for web traffic.'
    },
    EXCESSIVE_PERCENT_ENCODING: {
        type: 'EXCESSIVE_PERCENT_ENCODING',
        severity: SEVERITY.LOW,
        score: 15,
        message: 'URL path contains excessive percent-encoding sequences (%XX).'
    },
    HTTP_NO_TLS: {
        type: 'HTTP_NO_TLS',
        severity: SEVERITY.LOW,
        score: 10,
        message: 'URL uses unencrypted HTTP protocol without TLS protection.'
    },
    SUSPICIOUS_KEYWORD_MATCH: {
        type: 'SUSPICIOUS_KEYWORD_MATCH',
        severity: SEVERITY.LOW,
        score: 10,
        message: 'URL contains sensitive authentication or financial keywords.'
    },
    LONG_URL_LENGTH: {
        type: 'LONG_URL_LENGTH',
        severity: SEVERITY.LOW,
        score: 10,
        message: 'URL total length is suspiciously long (>75 characters).'
    },

    // 4. Payload & File Inspection
    KNOWN_MALWARE_SIGNATURE: {
        type: 'KNOWN_MALWARE_SIGNATURE',
        severity: SEVERITY.CRITICAL,
        score: 95,
        message: 'File matches known malware signature or suspicious piracy pattern.'
    },
    MAGIC_BYTE_MISMATCH: {
        type: 'MAGIC_BYTE_MISMATCH',
        severity: SEVERITY.CRITICAL,
        score: 80,
        message: 'Extension mismatch: Content binary signature does not match declared file extension.'
    },
    SUSPICIOUS_EXECUTABLE_BINARY: {
        type: 'SUSPICIOUS_EXECUTABLE_BINARY',
        severity: SEVERITY.HIGH,
        score: 50,
        message: 'File is a direct binary executable or script payload.'
    },
    DOUBLE_EXTENSION_EVASION: {
        type: 'DOUBLE_EXTENSION_EVASION',
        severity: SEVERITY.HIGH,
        score: 45,
        message: 'File uses double extension trick (e.g. document.pdf.exe).'
    },
    MACRO_ENABLED_DOCUMENT: {
        type: 'MACRO_ENABLED_DOCUMENT',
        severity: SEVERITY.MEDIUM,
        score: 30,
        message: 'File is a macro-enabled document format capable of executing scripts.'
    },
    ARCHIVE_PAYLOAD: {
        type: 'ARCHIVE_PAYLOAD',
        severity: SEVERITY.LOW,
        score: 15,
        message: 'File is a compressed archive containing embedded payloads.'
    }
};

module.exports = {
    SEVERITY,
    INDICATOR_DEFINITIONS
};
