const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluateRisk } = require('../../server/engine/riskEngine');
const { SEVERITY, INDICATOR_DEFINITIONS } = require('../../server/engine/indicators');

test('Risk Engine Evaluation Suite', async (t) => {
    await t.test('returns SAFE status for empty indicator list', () => {
        const verdict = evaluateRisk([], {}, { type: 'URL', value: 'https://example.com' });
        assert.equal(verdict.status, 'SAFE');
        assert.equal(verdict.riskScore, 0);
        assert.equal(verdict.confidence, 'LOW');
        assert.equal(verdict.indicators.length, 0);
        assert.equal(verdict.target.value, 'https://example.com');
    });

    await t.test('keeps score low for multiple weak LOW signals (non-linear dampening)', () => {
        const weakIndicators = [
            INDICATOR_DEFINITIONS.HTTP_NO_TLS,        // LOW (10)
            INDICATOR_DEFINITIONS.EXCESSIVE_HYPHENS,   // MEDIUM (15)
            INDICATOR_DEFINITIONS.LONG_URL_LENGTH      // LOW (10)
        ];

        const verdict = evaluateRisk(weakIndicators, {}, { type: 'URL', value: 'http://my-test-site.com/very-long-url-path' });
        assert.ok(verdict.riskScore <= 45);
        assert.notEqual(verdict.status, 'DANGEROUS');
    });

    await t.test('returns SUSPICIOUS status for HIGH severity indicator', () => {
        const indicators = [
            INDICATOR_DEFINITIONS.IP_ADDRESS_HOSTNAME // HIGH (45)
        ];

        const verdict = evaluateRisk(indicators, {}, { type: 'URL', value: 'http://192.168.1.1/login' });
        assert.equal(verdict.status, 'SUSPICIOUS');
        assert.ok(verdict.riskScore >= 30);
    });

    await t.test('returns DANGEROUS status for CRITICAL severity or Blacklist indicator', () => {
        const indicators = [
            INDICATOR_DEFINITIONS.KNOWN_BLACK_LIST_DOMAIN // CRITICAL (100)
        ];

        const verdict = evaluateRisk(indicators, {}, { type: 'URL', value: 'http://phishing-threat.com' });
        assert.equal(verdict.status, 'DANGEROUS');
        assert.equal(verdict.riskScore, 100);
        assert.equal(verdict.confidence, 'HIGH');
    });

    await t.test('caps risk score strictly at 100', () => {
        const indicators = [
            INDICATOR_DEFINITIONS.KNOWN_BLACK_LIST_DOMAIN,     // 100
            INDICATOR_DEFINITIONS.GOOGLE_SAFE_BROWSING_MALICIOUS, // 80
            INDICATOR_DEFINITIONS.IP_ADDRESS_HOSTNAME           // 45
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
