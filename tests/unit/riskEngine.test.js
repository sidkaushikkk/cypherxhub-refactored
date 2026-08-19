const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluateRisk } = require('../../server/engine/riskEngine');
const { SEVERITY, INDICATOR_DEFINITIONS } = require('../../server/engine/indicators');

test('Risk Engine Evaluation Suite', async (t) => {
    await t.test('returns SAFE status when Safe Browsing is CLEAN and no malicious indicators', () => {
        const threatIntel = { googleSafeBrowsing: { status: 'CLEAN' } };
        const verdict = evaluateRisk([], threatIntel, { type: 'URL', value: 'https://example.com' });
        assert.equal(verdict.status, 'SAFE');
        assert.equal(verdict.riskScore, 0);
        assert.equal(verdict.confidence, 'LOW');
        assert.equal(verdict.indicators.length, 0);
        assert.equal(verdict.target.value, 'https://example.com');
    });

    await t.test('returns UNVERIFIED status when Safe Browsing is UNAVAILABLE without local threat indicators', () => {
        const threatIntel = { googleSafeBrowsing: { status: 'UNAVAILABLE' } };
        const verdict = evaluateRisk([], threatIntel, { type: 'URL', value: 'https://example.com' });
        assert.equal(verdict.status, 'UNVERIFIED');
        assert.notEqual(verdict.status, 'SAFE');
        assert.ok(verdict.recommendation.includes('UNVERIFIED'));
    });

    await t.test('returns UNVERIFIED status when Safe Browsing has ERROR without local threat indicators', () => {
        const threatIntel = { googleSafeBrowsing: { status: 'ERROR' } };
        const verdict = evaluateRisk([], threatIntel, { type: 'URL', value: 'https://example.com' });
        assert.equal(verdict.status, 'UNVERIFIED');
        assert.notEqual(verdict.status, 'SAFE');
    });

    await t.test('returns DANGEROUS status when Safe Browsing is MALICIOUS', () => {
        const threatIntel = { googleSafeBrowsing: { status: 'MALICIOUS' } };
        const verdict = evaluateRisk([INDICATOR_DEFINITIONS.GOOGLE_SAFE_BROWSING_MALICIOUS], threatIntel, { type: 'URL', value: 'https://evil.com' });
        assert.equal(verdict.status, 'DANGEROUS');
        assert.equal(verdict.confidence, 'HIGH');
    });

    await t.test('returns DANGEROUS status with local strong malicious indicators even when Safe Browsing is UNAVAILABLE', () => {
        const threatIntel = { googleSafeBrowsing: { status: 'UNAVAILABLE' } };
        const indicators = [INDICATOR_DEFINITIONS.KNOWN_BLACK_LIST_DOMAIN];
        const verdict = evaluateRisk(indicators, threatIntel, { type: 'URL', value: 'https://phishing.com' });
        assert.equal(verdict.status, 'DANGEROUS');
        assert.equal(verdict.riskScore, 100);
    });

    await t.test('keeps score low for multiple weak LOW signals (non-linear dampening)', () => {
        const weakIndicators = [
            INDICATOR_DEFINITIONS.HTTP_NO_TLS,
            INDICATOR_DEFINITIONS.EXCESSIVE_HYPHENS,
            INDICATOR_DEFINITIONS.LONG_URL_LENGTH
        ];

        const verdict = evaluateRisk(weakIndicators, { googleSafeBrowsing: { status: 'CLEAN' } }, { type: 'URL', value: 'http://my-test-site.com/very-long-url-path' });
        assert.ok(verdict.riskScore <= 45);
        assert.notEqual(verdict.status, 'DANGEROUS');
    });

    await t.test('returns SUSPICIOUS status for HIGH severity indicator even when Safe Browsing is UNAVAILABLE', () => {
        const indicators = [
            INDICATOR_DEFINITIONS.IP_ADDRESS_HOSTNAME
        ];

        const verdict = evaluateRisk(indicators, { googleSafeBrowsing: { status: 'UNAVAILABLE' } }, { type: 'URL', value: 'http://192.168.1.1/login' });
        assert.equal(verdict.status, 'SUSPICIOUS');
        assert.ok(verdict.riskScore >= 30);
    });

    await t.test('caps risk score strictly at 100', () => {
        const indicators = [
            INDICATOR_DEFINITIONS.KNOWN_BLACK_LIST_DOMAIN,
            INDICATOR_DEFINITIONS.GOOGLE_SAFE_BROWSING_MALICIOUS,
            INDICATOR_DEFINITIONS.IP_ADDRESS_HOSTNAME
        ];

        const verdict = evaluateRisk(indicators, {}, { type: 'URL', value: 'http://192.168.1.1' });
        assert.equal(verdict.riskScore, 100);
    });

    await t.test('produces standardized unified result object structure', () => {
        const verdict = evaluateRisk([], {}, { type: 'URL', value: 'https://example.com' });
        assert.ok(verdict.scanType);
        assert.ok(verdict.status);
        assert.strictEqual(typeof verdict.riskScore, 'number');
        assert.ok(verdict.confidence);
        assert.ok(verdict.target);
        assert.ok(Array.isArray(verdict.indicators));
        assert.ok(Array.isArray(verdict.reasons));
        assert.ok(verdict.recommendation);
        assert.ok(verdict.timestamp);
    });
});
