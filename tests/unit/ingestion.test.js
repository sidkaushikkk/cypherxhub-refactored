const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeUrl, validateRecord } = require('../../evaluation/ingestion/normalize');
const { 
    processDatasetQuality, 
    createDatasetSplits, 
    createBalancedDataset 
} = require('../../evaluation/ingestion/dataQuality');

test('Dataset Ingestion & Quality Control Suite', async (t) => {
    await t.test('normalizeUrl standardizes casing, trims whitespace, and removes fragments', () => {
        const res = normalizeUrl('   https://Example.COM:443/Path/To/Page?q=test#section  ');
        assert.equal(res.isValid, true);
        assert.equal(res.normalizedUrl, 'https://example.com/Path/To/Page?q=test');
    });

    await t.test('normalizeUrl auto-prepends https protocol when omitted', () => {
        const res = normalizeUrl('github.com/login');
        assert.equal(res.isValid, true);
        assert.equal(res.normalizedUrl, 'https://github.com/login');
    });

    await t.test('normalizeUrl rejects dangerous or unsupported non-web schemes', () => {
        assert.equal(normalizeUrl('javascript:alert(1)').isValid, false);
        assert.equal(normalizeUrl('file:///etc/passwd').isValid, false);
        assert.equal(normalizeUrl('data:text/html,test').isValid, false);
        assert.equal(normalizeUrl('ftp://ftp.example.com').isValid, false);
        assert.equal(normalizeUrl('').isValid, false);
    });

    await t.test('validateRecord accepts valid record schemas', () => {
        const raw = {
            url: 'https://example.com',
            label: 'BENIGN',
            category: 'normal_website',
            source: 'tranco',
            sourceId: '100',
            collectedAt: '2026-08-01T00:00:00Z'
        };

        const res = validateRecord(raw);
        assert.equal(res.isValid, true);
        assert.equal(res.record.label, 'BENIGN');
        assert.equal(res.record.source, 'tranco');
    });

    await t.test('validateRecord rejects invalid ground-truth labels', () => {
        const res = validateRecord({ url: 'https://example.com', label: 'MAYBE_SAFE' });
        assert.equal(res.isValid, false);
        assert.ok(res.error.includes('INVALID_GROUND_TRUTH_LABEL'));
    });

    await t.test('processDatasetQuality merges duplicate URLs and combines multi-source provenance', () => {
        const records = [
            { url: 'https://phish.example.com', label: 'MALICIOUS', source: 'phishtank', sourceId: '101' },
            { url: 'https://phish.example.com', label: 'MALICIOUS', source: 'openphish', sourceId: '202' },
            { url: 'https://legit.example.com', label: 'BENIGN', source: 'tranco' }
        ];

        const { cleanRecords, qualityReport } = processDatasetQuality(records);
        assert.equal(qualityReport.duplicatesRemoved, 1);
        assert.equal(cleanRecords.length, 2);

        const phish = cleanRecords.find(r => r.url.includes('phish'));
        assert.ok(phish.sources.includes('phishtank'));
        assert.ok(phish.sources.includes('openphish'));
    });

    await t.test('processDatasetQuality detects and excludes label conflicts', () => {
        const records = [
            { url: 'https://ambiguous.example.com', label: 'BENIGN', source: 'tranco' },
            { url: 'https://ambiguous.example.com', label: 'MALICIOUS', source: 'phishtank' },
            { url: 'https://clean.example.com', label: 'BENIGN', source: 'tranco' }
        ];

        const { cleanRecords, qualityReport, conflicts } = processDatasetQuality(records);
        assert.equal(qualityReport.conflictsExcluded, 1);
        assert.equal(conflicts.length, 2);
        assert.equal(cleanRecords.length, 1);
        assert.equal(cleanRecords[0].url, 'https://clean.example.com/');
    });

    await t.test('createDatasetSplits partitions dataset into 60/20/20 temporal splits', () => {
        const records = [
            { url: 'https://site1.com', collectedAt: '2026-01-01T00:00:00Z' },
            { url: 'https://site2.com', collectedAt: '2026-02-01T00:00:00Z' },
            { url: 'https://site3.com', collectedAt: '2026-03-01T00:00:00Z' },
            { url: 'https://site4.com', collectedAt: '2026-04-01T00:00:00Z' },
            { url: 'https://site5.com', collectedAt: '2026-05-01T00:00:00Z' }
        ];

        const splits = createDatasetSplits(records);
        assert.equal(splits.isTemporal, true);
        assert.equal(splits.development.length, 3); // 60%
        assert.equal(splits.validation.length, 1);  // 20%
        assert.equal(splits.test.length, 1);        // 20%
        assert.equal(splits.development[0].url, 'https://site1.com');
        assert.equal(splits.test[0].url, 'https://site5.com');
    });

    await t.test('createBalancedDataset produces equal 50/50 class balance', () => {
        const records = [
            { url: 'https://b1.com', label: 'BENIGN' },
            { url: 'https://b2.com', label: 'BENIGN' },
            { url: 'https://b3.com', label: 'BENIGN' },
            { url: 'https://m1.com', label: 'MALICIOUS' }
        ];

        const balanced = createBalancedDataset(records);
        assert.equal(balanced.length, 2);
        assert.equal(balanced.filter(r => r.label === 'BENIGN').length, 1);
        assert.equal(balanced.filter(r => r.label === 'MALICIOUS').length, 1);
    });
});
