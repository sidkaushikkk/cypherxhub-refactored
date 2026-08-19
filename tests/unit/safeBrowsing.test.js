const test = require('node:test');
const assert = require('node:assert/strict');
const axios = require('axios');
const config = require('../../server/config/env');
const { checkGoogleSafeBrowsing } = require('../../server/services/safeBrowsing');

test('Safe Browsing API Service Suite', async (t) => {
    await t.test('returns UNAVAILABLE status when API key is not configured', async () => {
        const originalKey = config.googleSafeBrowsingApiKey;
        config.googleSafeBrowsingApiKey = '';

        const result = await checkGoogleSafeBrowsing('https://example.com');
        assert.equal(result.status, 'UNAVAILABLE');

        config.googleSafeBrowsingApiKey = originalKey;
    });

    await t.test('handles CLEAN API response', async () => {
        const originalKey = config.googleSafeBrowsingApiKey;
        config.googleSafeBrowsingApiKey = 'mock_api_key';

        const originalPost = axios.post;
        axios.post = async () => ({
            data: { matches: [] }
        });

        const result = await checkGoogleSafeBrowsing('https://example.com');
        assert.equal(result.status, 'CLEAN');

        axios.post = originalPost;
        config.googleSafeBrowsingApiKey = originalKey;
    });

    await t.test('handles MALICIOUS API response', async () => {
        const originalKey = config.googleSafeBrowsingApiKey;
        config.googleSafeBrowsingApiKey = 'mock_api_key';

        const originalPost = axios.post;
        axios.post = async () => ({
            data: {
                matches: [{ threatType: 'MALWARE', threat: { url: 'https://evil.com' } }]
            }
        });

        const result = await checkGoogleSafeBrowsing('https://evil.com');
        assert.equal(result.status, 'MALICIOUS');
        assert.equal(result.matches.length, 1);

        axios.post = originalPost;
        config.googleSafeBrowsingApiKey = originalKey;
    });

    await t.test('handles request TIMEOUT gracefully without throwing', async () => {
        const originalKey = config.googleSafeBrowsingApiKey;
        config.googleSafeBrowsingApiKey = 'mock_api_key';

        const originalPost = axios.post;
        axios.post = async () => {
            const err = new Error('timeout of 5000ms exceeded');
            err.code = 'ECONNABORTED';
            throw err;
        };

        const result = await checkGoogleSafeBrowsing('https://slow-site.com');
        assert.equal(result.status, 'UNAVAILABLE');
        assert.ok(result.reason.includes('timed out'));

        axios.post = originalPost;
        config.googleSafeBrowsingApiKey = originalKey;
    });

    await t.test('handles API NETWORK ERROR gracefully', async () => {
        const originalKey = config.googleSafeBrowsingApiKey;
        config.googleSafeBrowsingApiKey = 'mock_api_key';

        const originalPost = axios.post;
        axios.post = async () => {
            throw new Error('Network Error');
        };

        const result = await checkGoogleSafeBrowsing('https://error-site.com');
        assert.equal(result.status, 'ERROR');

        axios.post = originalPost;
        config.googleSafeBrowsingApiKey = originalKey;
    });
});
