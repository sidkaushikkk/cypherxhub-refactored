/**
 * Typosquatting and Brand Similarity Detection Utility
 * 
 * Analyzes hostnames for domain impersonation, character substitution,
 * Levenshtein edit distance, and brand targeting.
 */

// Curated list of high-value brands frequently targeted by phishing
const BRAND_CATALOG = [
    { name: 'paypal', domain: 'paypal.com' },
    { name: 'google', domain: 'google.com' },
    { name: 'github', domain: 'github.com' },
    { name: 'facebook', domain: 'facebook.com' },
    { name: 'microsoft', domain: 'microsoft.com' },
    { name: 'apple', domain: 'apple.com' },
    { name: 'amazon', domain: 'amazon.com' },
    { name: 'netflix', domain: 'netflix.com' },
    { name: 'instagram', domain: 'instagram.com' },
    { name: 'binance', domain: 'binance.com' },
    { name: 'coinbase', domain: 'coinbase.com' },
    { name: 'twitter', domain: 'twitter.com' },
    { name: 'linkedin', domain: 'linkedin.com' },
    { name: 'telegram', domain: 'telegram.org' },
    { name: 'whatsapp', domain: 'whatsapp.com' },
    { name: 'discord', domain: 'discord.com' },
    { name: 'metamask', domain: 'metamask.io' }
];

// Common character substitution map used in leetspeak evasions
const CHAR_SUBS = {
    '0': 'o',
    '1': 'i', // or l
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '$': 's'
};

/**
 * Check if hostname belongs to an official trusted brand domain or subdomain
 */
function isOfficialBrandDomain(hostname) {
    if (!hostname || typeof hostname !== 'string') return false;
    const lowerHost = hostname.toLowerCase();
    for (const brand of BRAND_CATALOG) {
        if (lowerHost === brand.domain || lowerHost.endsWith('.' + brand.domain)) {
            return true;
        }
    }
    return false;
}

/**
 * Calculate Levenshtein edit distance between two strings
 */
function calculateLevenshteinDistance(str1, str2) {
    if (!str1 || !str2) return (str1 || str2 || '').length;

    const len1 = str1.length;
    const len2 = str2.length;
    const matrix = Array.from({ length: len1 + 1 }, () => new Array(len2 + 1).fill(0));

    for (let i = 0; i <= len1; i++) matrix[i][0] = i;
    for (let j = 0; j <= len2; j++) matrix[0][j] = j;

    for (let i = 1; i <= len1; i++) {
        for (let j = 1; j <= len2; j++) {
            const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,       // Deletion
                matrix[i][j - 1] + 1,       // Insertion
                matrix[i - 1][j - 1] + cost // Substitution
            );
        }
    }

    return matrix[len1][len2];
}

/**
 * Normalize string by replacing common leetspeak characters
 */
function normalizeLeetspeak(str) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        const ch = str[i].toLowerCase();
        if (CHAR_SUBS[ch]) {
            result += CHAR_SUBS[ch];
        } else {
            result += ch;
        }
    }
    return result;
}

/**
 * Extract second-level domain (SLD) / base domain from hostname
 * Example: 'login.paypa1.com' -> 'paypa1'
 */
function extractBaseSld(hostname) {
    if (!hostname || typeof hostname !== 'string') return '';
    
    // If IP address, return as is
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname)) return hostname;

    const parts = hostname.toLowerCase().split('.');
    if (parts.length <= 1) return parts[0] || '';
    
    // Standard TLD heuristic (e.g. .co.uk vs .com)
    if (parts.length >= 3 && ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'].includes(parts[parts.length - 2])) {
        return parts[parts.length - 3];
    }

    return parts[parts.length - 2];
}

/**
 * Perform typosquatting and brand impersonation analysis on hostname
 * 
 * @param {string} hostname
 * @returns {Object|null} Match details or null
 */
function analyzeTyposquatting(hostname) {
    if (!hostname || typeof hostname !== 'string') return null;

    const lowerHost = hostname.toLowerCase();

    // Exact match or official subdomain of a brand is NOT typosquatting
    if (isOfficialBrandDomain(lowerHost)) {
        return null;
    }

    const sld = extractBaseSld(lowerHost);
    if (!sld || sld.length < 3) return null;

    for (const brand of BRAND_CATALOG) {
        const brandName = brand.name;

        // 1. Direct Leetspeak / Character Substitution Check (e.g. paypa1, g00gle)
        const normalizedSld = normalizeLeetspeak(sld);
        if (normalizedSld === brandName && sld !== brandName) {
            return {
                brand: brandName,
                officialDomain: brand.domain,
                technique: 'CHARACTER_SUBSTITUTION',
                message: `Domain '${sld}' uses character substitutions (leetspeak) to impersonate '${brandName}'.`,
                similarity: 0.95
            };
        }

        // 2. Levenshtein Edit Distance Check (distance of 1 or 2 edits)
        const distance = calculateLevenshteinDistance(sld, brandName);
        const maxLength = Math.max(sld.length, brandName.length);
        const similarity = 1 - (distance / maxLength);

        const maxAllowedDistance = brandName.length <= 5 ? 1 : 2;

        if (distance > 0 && distance <= maxAllowedDistance && similarity >= 0.75) {
            let technique = 'EDIT_DISTANCE_TYPOSQUAT';
            if (sld.length < brandName.length) technique = 'MISSING_CHARACTER';
            else if (sld.length > brandName.length) technique = 'INSERTED_CHARACTER';
            else if (distance === 1) technique = 'SINGLE_CHARACTER_TYPO';

            return {
                brand: brandName,
                officialDomain: brand.domain,
                technique,
                distance,
                similarity: Number(similarity.toFixed(2)),
                message: `Domain '${sld}' closely resembles protected brand '${brandName}' (${Math.round(similarity * 100)}% similarity, ${distance} edit difference).`
            };
        }

        // 3. Hyphenated Brand Impersonation (e.g. pay-pal-verify.com or login-paypal.com)
        if (sld.includes('-')) {
            const hyphenParts = sld.split('-');
            for (const part of hyphenParts) {
                if (part === brandName) {
                    return {
                        brand: brandName,
                        officialDomain: brand.domain,
                        technique: 'HYPHENATED_BRAND_IMPERSONATION',
                        message: `Domain combines brand name '${brandName}' with hyphens to deceive users.`,
                        similarity: 0.85
                    };
                }
            }
        }
    }

    return null;
}

module.exports = {
    BRAND_CATALOG,
    isOfficialBrandDomain,
    calculateLevenshteinDistance,
    normalizeLeetspeak,
    extractBaseSld,
    analyzeTyposquatting
};
