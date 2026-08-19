const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { loadDataset } = require('../../evaluation/evaluate');
const { 
    calculateConfusionMatrix, 
    calculateMetrics, 
    evaluateThresholds, 
    breakdownByCategory 
} = require('../../evaluation/metrics');

test('Evaluation System & Metrics Suite', async (t) => {
    await t.test('loadDataset successfully loads and validates curated seed datasets', () => {
        const benignPath = path.join(__dirname, '../../evaluation/datasets/benign.json');
        const maliciousPath = path.join(__dirname, '../../evaluation/datasets/malicious.json');

        const benign = loadDataset(benignPath);
        const malicious = loadDataset(maliciousPath);

        assert.ok(Array.isArray(benign));
        assert.ok(benign.length >= 20);
        assert.equal(benign.every(b => b.label === 'BENIGN'), true);

        assert.ok(Array.isArray(malicious));
        assert.ok(malicious.length >= 20);
        assert.equal(malicious.every(m => m.label === 'MALICIOUS'), true);
    });

    await t.test('calculateConfusionMatrix accurately counts TP, TN, FP, FN', () => {
        const mockResults = [
            { groundTruth: 'MALICIOUS', predictedLabel: 'MALICIOUS' }, // TP
            { groundTruth: 'MALICIOUS', predictedLabel: 'MALICIOUS' }, // TP
            { groundTruth: 'MALICIOUS', predictedLabel: 'BENIGN' },    // FN
            { groundTruth: 'BENIGN', predictedLabel: 'BENIGN' },       // TN
            { groundTruth: 'BENIGN', predictedLabel: 'BENIGN' },       // TN
            { groundTruth: 'BENIGN', predictedLabel: 'BENIGN' },       // TN
            { groundTruth: 'BENIGN', predictedLabel: 'MALICIOUS' }     // FP
        ];

        const cm = calculateConfusionMatrix(mockResults);
        assert.equal(cm.tp, 2);
        assert.equal(cm.tn, 3);
        assert.equal(cm.fp, 1);
        assert.equal(cm.fn, 1);
        assert.equal(cm.total, 7);
    });

    await t.test('calculateMetrics accurately computes Precision, Recall, Accuracy, F1, FPR, FNR', () => {
        // TP=8, TN=10, FP=2, FN=2 (Total=22)
        const cm = { tp: 8, tn: 10, fp: 2, fn: 2, total: 22 };
        const metrics = calculateMetrics(cm);

        // Accuracy = (8+10)/22 = 18/22 = 81.8%
        assert.equal(metrics.accuracy, 81.8);
        // Precision = 8/(8+2) = 8/10 = 80.0%
        assert.equal(metrics.precision, 80.0);
        // Recall = 8/(8+2) = 8/10 = 80.0%
        assert.equal(metrics.recall, 80.0);
        // F1 = 80.0%
        assert.equal(metrics.f1Score, 80.0);
        // FPR = 2/(2+10) = 2/12 = 16.7%
        assert.equal(metrics.falsePositiveRate, 16.7);
        // FNR = 2/(8+2) = 2/10 = 20.0%
        assert.equal(metrics.falseNegativeRate, 20.0);
    });

    await t.test('calculateMetrics gracefully handles division by zero (empty counts)', () => {
        const cm = { tp: 0, tn: 0, fp: 0, fn: 0, total: 0 };
        const metrics = calculateMetrics(cm);

        assert.equal(metrics.accuracy, 0);
        assert.equal(metrics.precision, 0);
        assert.equal(metrics.recall, 0);
        assert.equal(metrics.f1Score, 0);
    });

    await t.test('evaluateThresholds accurately analyzes different score cutoff points', () => {
        const mockResults = [
            { groundTruth: 'MALICIOUS', riskScore: 75 },
            { groundTruth: 'MALICIOUS', riskScore: 45 },
            { groundTruth: 'BENIGN', riskScore: 10 },
            { groundTruth: 'BENIGN', riskScore: 0 }
        ];

        const sweep = evaluateThresholds(mockResults, [40, 70]);
        assert.equal(sweep.length, 2);

        // At threshold >= 40: items with 75 and 45 are predicted MALICIOUS -> TP=2, FP=0, FN=0, TN=2
        assert.equal(sweep[0].threshold, 40);
        assert.equal(sweep[0].tp, 2);
        assert.equal(sweep[0].fp, 0);
        assert.equal(sweep[0].recall, 100);

        // At threshold >= 70: only 75 is predicted MALICIOUS -> TP=1, FP=0, FN=1, TN=2
        assert.equal(sweep[1].threshold, 70);
        assert.equal(sweep[1].tp, 1);
        assert.equal(sweep[1].fn, 1);
        assert.equal(sweep[1].recall, 50);
    });

    await t.test('breakdownByCategory groups results and calculates accuracy per category', () => {
        const mockResults = [
            { category: 'typosquatting', isCorrect: true, groundTruth: 'MALICIOUS' },
            { category: 'typosquatting', isCorrect: false, groundTruth: 'MALICIOUS' },
            { category: 'normal_website', isCorrect: true, groundTruth: 'BENIGN' }
        ];

        const breakdown = breakdownByCategory(mockResults);
        assert.equal(breakdown.typosquatting.samples, 2);
        assert.equal(breakdown.typosquatting.correct, 1);
        assert.equal(breakdown.typosquatting.accuracy, 50);

        assert.equal(breakdown.normal_website.samples, 1);
        assert.equal(breakdown.normal_website.correct, 1);
        assert.equal(breakdown.normal_website.accuracy, 100);
    });
});
