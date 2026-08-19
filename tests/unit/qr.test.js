const test = require('node:test');
const assert = require('node:assert/strict');
const { scanUrl } = require('../../server/services/urlScanner');
const axios = require('axios');

// Strict HTTP(S) URL validator matching the frontend QR inspection logic
function isHttpUrl(str) {
    if (!str || typeof str !== 'string') return false;
    const trimmed = str.trim();
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return false;
    try {
        const parsed = new URL(trimmed);
        return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && !!parsed.hostname;
    } catch {
        return false;
    }
}

test('QR Payload Validation & Scanner Suite', async (t) => {
    let originalAxiosPost;

    t.before(() => {
        originalAxiosPost = axios.post;
        axios.post = async () => ({
            data: { matches: [] } // Mock clean Safe Browsing
        });
    });

    t.after(() => {
        axios.post = originalAxiosPost;
    });

    await t.test('accepts valid HTTP(S) URLs for QR payload', () => {
        assert.equal(isHttpUrl('https://github.com'), true);
        assert.equal(isHttpUrl('http://example.com/test'), true);
        assert.equal(isHttpUrl('https://paypal.com@evil.com/login'), true);
    });

    await t.test('rejects plain text and dangerous non-HTTP schemes for QR payload', () => {
        assert.equal(isHttpUrl('HELLO-CYPHERX-TEST'), false);
        assert.equal(isHttpUrl('some random wifi password string'), false);
        assert.equal(isHttpUrl('javascript:alert(1)'), false);
        assert.equal(isHttpUrl('file:///etc/passwd'), false);
        assert.equal(isHttpUrl('data:text/html,test'), false);
        assert.equal(isHttpUrl('ftp://ftp.example.com'), false);
    });

    await t.test('scans safe QR URL payload (https://github.com)', async () => {
        const payload = 'https://github.com';
        assert.equal(isHttpUrl(payload), true);

        const verdict = await scanUrl(payload, 'QR Inspection');
        assert.equal(verdict.status, 'SAFE');
        assert.equal(verdict.riskScore, 0);
        assert.equal(verdict.scanType, 'QR');
    });

    await t.test('scans deceptive userinfo QR URL payload (https://paypal.com@evil.com/login)', async () => {
        const payload = 'https://paypal.com@evil.com/login';
        assert.equal(isHttpUrl(payload), true);

        const verdict = await scanUrl(payload, 'QR Inspection');
        assert.ok(verdict.status === 'SUSPICIOUS' || verdict.status === 'DANGEROUS');
        assert.ok(verdict.riskScore >= 60);
        assert.equal(verdict.scanType, 'QR');
    });

    await t.test('plain-text QR payload (HELLO-CYPHERX-TEST) is blocked from URL scanner', () => {
        const payload = 'HELLO-CYPHERX-TEST';
        const isUrl = isHttpUrl(payload);
        assert.equal(isUrl, false);
        // Non-URL is handled locally by UI, not dispatched to scanUrl
    });
});
