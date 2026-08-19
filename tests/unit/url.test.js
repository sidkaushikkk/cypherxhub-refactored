const test = require('node:test');
const assert = require('node:assert/strict');
const { 
    validateAndNormalizeUrl, 
    isIpAddress, 
    getSuspiciousTld, 
    detectHomographUnicode, 
    analyzeQueryParameters, 
    countPercentEncodings 
} = require('../../server/utils/url');

test('URL Utility - Normalization Layer', async (t) => {
    await t.test('normalizes missing protocol to http', () => {
        const result = validateAndNormalizeUrl('example.com');
        assert.equal(result.protocol, 'http:');
        assert.equal(result.hostname, 'example.com');
        assert.equal(result.normalizedUrl, 'http://example.com/');
    });

    await t.test('retains valid https protocol', () => {
        const result = validateAndNormalizeUrl('https://google.com/path?q=1');
        assert.equal(result.protocol, 'https:');
        assert.equal(result.hostname, 'google.com');
        assert.equal(result.pathname, '/path');
    });

    await t.test('rejects unsafe protocols (javascript:, file:, data:)', () => {
        assert.throws(() => validateAndNormalizeUrl('javascript:alert(1)'));
        assert.throws(() => validateAndNormalizeUrl('file:///etc/passwd'));
        assert.throws(() => validateAndNormalizeUrl('data:text/html,<script>'));
    });

    await t.test('detects IPv4 and IPv6 hosts correctly', () => {
        assert.equal(isIpAddress('192.168.1.1'), true);
        assert.equal(isIpAddress('10.0.0.1'), true);
        assert.equal(isIpAddress('google.com'), false);
    });

    await t.test('extracts suspicious TLDs', () => {
        assert.equal(getSuspiciousTld('phishing-site.xyz'), '.xyz');
        assert.equal(getSuspiciousTld('login-verify.top'), '.top');
        assert.equal(getSuspiciousTld('github.com'), null);
    });

    await t.test('detects deceptive userinfo authority (@ trick)', () => {
        const result = validateAndNormalizeUrl('https://paypal.com@evil.com/login');
        assert.equal(result.username, 'paypal.com');
        assert.equal(result.hostname, 'evil.com');
    });

    await t.test('detects Punycode and Unicode homograph characters', () => {
        const punycodeRes = detectHomographUnicode('xn--e1afmkfd.xn--p1ai');
        assert.equal(punycodeRes.isPunycode, true);

        const cyrillicHomographRes = detectHomographUnicode('pаypal.com'); // Uses Cyrillic 'а' (\u0430)
        assert.equal(cyrillicHomographRes.hasHomograph, true);

        const standardAsciiRes = detectHomographUnicode('paypal.com');
        assert.equal(standardAsciiRes, null);
    });

    await t.test('analyzes query parameters for embedded redirects', () => {
        const urlData = validateAndNormalizeUrl('https://example.com/?redirect=https://evil.com');
        const redirectRes = analyzeQueryParameters(urlData.searchParams);
        assert.notEqual(redirectRes, null);
        assert.equal(redirectRes.paramKey, 'redirect');

        const cleanUrlData = validateAndNormalizeUrl('https://example.com/?page=2');
        assert.equal(analyzeQueryParameters(cleanUrlData.searchParams), null);
    });

    await t.test('counts percent encodings', () => {
        assert.equal(countPercentEncodings('/path%20with%20spaces%21'), 3);
        assert.equal(countPercentEncodings('/normal-path'), 0);
    });
});
