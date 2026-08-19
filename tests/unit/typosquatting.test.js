const test = require('node:test');
const assert = require('node:assert/strict');
const { 
    calculateLevenshteinDistance, 
    normalizeLeetspeak, 
    extractBaseSld, 
    analyzeTyposquatting 
} = require('../../server/utils/typosquatting');

test('Typosquatting Utility Suite', async (t) => {
    await t.test('calculates exact Levenshtein edit distance', () => {
        assert.equal(calculateLevenshteinDistance('paypal', 'paypal'), 0);
        assert.equal(calculateLevenshteinDistance('paypal', 'paypa1'), 1);
        assert.equal(calculateLevenshteinDistance('google', 'g00gle'), 2);
    });

    await t.test('normalizes leetspeak substitutions', () => {
        assert.equal(normalizeLeetspeak('paypa1'), 'paypai');
        assert.equal(normalizeLeetspeak('g00gle'), 'google');
        assert.equal(normalizeLeetspeak('micro$oft'), 'microsoft');
    });

    await t.test('extracts second-level domain (SLD)', () => {
        assert.equal(extractBaseSld('login.verify.paypal.com'), 'paypal');
        assert.equal(extractBaseSld('paypa1.xyz'), 'paypa1');
        assert.equal(extractBaseSld('192.168.1.1'), '192.168.1.1');
    });

    await t.test('flags character substitution typosquats (paypa1, g00gle)', () => {
        const res1 = analyzeTyposquatting('paypa1.com');
        assert.notEqual(res1, null);
        assert.equal(res1.brand, 'paypal');

        const res2 = analyzeTyposquatting('g00gle.com');
        assert.notEqual(res2, null);
        assert.equal(res2.brand, 'google');
    });

    await t.test('flags edit distance typosquats (githab.com)', () => {
        const res = analyzeTyposquatting('githab.com');
        assert.notEqual(res, null);
        assert.equal(res.brand, 'github');
    });

    await t.test('flags hyphenated brand impersonation (login-paypal.com)', () => {
        const res = analyzeTyposquatting('login-paypal.com');
        assert.notEqual(res, null);
        assert.equal(res.brand, 'paypal');
    });

    await t.test('does NOT flag legitimate brand domains as typosquats', () => {
        assert.equal(analyzeTyposquatting('paypal.com'), null);
        assert.equal(analyzeTyposquatting('google.com'), null);
        assert.equal(analyzeTyposquatting('github.com'), null);
        assert.equal(analyzeTyposquatting('mycompany-example.com'), null);
    });
});
