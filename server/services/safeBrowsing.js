const axios = require('axios');
const config = require('../config/env');
const logger = require('../utils/logger');

/**
 * Query Google Safe Browsing API v4 with timeout and detailed error classification
 * 
 * @param {string} url 
 * @returns {Promise<Object>} { status: 'CLEAN' | 'MALICIOUS' | 'UNAVAILABLE' | 'ERROR', reason?: string, matches?: Array }
 */
async function checkGoogleSafeBrowsing(url) {
    if (!config.googleSafeBrowsingApiKey) {
        return { 
            status: 'UNAVAILABLE', 
            reason: 'Google Safe Browsing API key is not configured.' 
        };
    }

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.googleSafeBrowsingApiKey}`;
    const body = {
        client: {
            clientId: "cypherx",
            clientVersion: "2.4"
        },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [
                { url }
            ]
        }
    };

    try {
        const response = await axios.post(endpoint, body, {
            timeout: config.safeBrowsingTimeoutMs || 5000,
            headers: { 'Content-Type': 'application/json' }
        });

        if (response.data && response.data.matches && response.data.matches.length > 0) {
            return {
                status: 'MALICIOUS',
                matches: response.data.matches,
                reason: 'Flagged as malicious by Google Safe Browsing API.'
            };
        }

        return { 
            status: 'CLEAN',
            reason: 'No matches found in Google Safe Browsing database.'
        };
    } catch (err) {
        if (err.code === 'ECONNABORTED') {
            logger.warn('Google Safe Browsing API request timed out (5s).');
            return {
                status: 'UNAVAILABLE',
                reason: 'Google Safe Browsing API request timed out after 5000ms.'
            };
        }

        const statusCode = err.response ? err.response.status : null;
        const errorMessage = err.response && err.response.data && err.response.data.error 
            ? err.response.data.error.message 
            : err.message;

        logger.warn(`Google Safe Browsing API check failed (${statusCode || 'Network Error'}): ${errorMessage}`);

        return {
            status: 'ERROR',
            reason: `Safe Browsing API check failed: ${errorMessage}`
        };
    }
}

module.exports = {
    checkGoogleSafeBrowsing
};
