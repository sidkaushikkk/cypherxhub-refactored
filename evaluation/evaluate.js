const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { scanUrl } = require('../server/services/urlScanner');
const { 
    calculateConfusionMatrix, 
    calculateMetrics, 
    evaluateThresholds, 
    breakdownByCategory 
} = require('./metrics');

/**
 * Load and validate JSON dataset file
 */
function loadDataset(filePath) {
    if (!fs.existsSync(filePath)) {
        throw new Error(`Dataset file not found at: ${filePath}`);
    }
    const rawData = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(rawData);

    if (!Array.isArray(parsed)) {
        throw new Error(`Dataset file must contain a JSON array: ${filePath}`);
    }

    return parsed.map((entry, idx) => {
        if (!entry.url || typeof entry.url !== 'string') {
            throw new Error(`Missing or invalid 'url' at index ${idx} in ${filePath}`);
        }
        if (!['BENIGN', 'MALICIOUS'].includes(entry.label)) {
            throw new Error(`Invalid ground-truth label '${entry.label}' at index ${idx} in ${filePath}. Must be 'BENIGN' or 'MALICIOUS'.`);
        }
        return entry;
    });
}

/**
 * Run evaluation benchmark on dataset
 */
async function runBenchmark(options = {}) {
    const benignPath = options.benignPath || path.join(__dirname, 'datasets/benign.json');
    const maliciousPath = options.maliciousPath || path.join(__dirname, 'datasets/malicious.json');
    const saveResults = options.saveResults !== false;

    // Load ground-truth datasets
    const benignData = loadDataset(benignPath);
    const maliciousData = loadDataset(maliciousPath);
    const fullDataset = [...benignData, ...maliciousData];

    // Mock Google Safe Browsing to ensure 100% deterministic, hermetic benchmarking
    const originalAxiosPost = axios.post;
    axios.post = async () => ({
        data: { matches: [] } // Deterministic clean baseline (tests local detection heuristics)
    });

    const evaluatedResults = [];

    try {
        for (const item of fullDataset) {
            const verdict = await scanUrl(item.url, 'Evaluation Benchmark');
            
            // Map CypherX multi-tier status to binary prediction for benchmark comparison
            // SUSPICIOUS and DANGEROUS map to MALICIOUS
            // SAFE and UNVERIFIED map to BENIGN
            const predictedLabel = (verdict.status === 'SUSPICIOUS' || verdict.status === 'DANGEROUS') 
                ? 'MALICIOUS' 
                : 'BENIGN';

            const isCorrect = item.label === predictedLabel;

            evaluatedResults.push({
                url: item.url,
                category: item.category || 'uncategorized',
                source: item.source || 'UNKNOWN',
                groundTruth: item.label,
                predictedLabel,
                cypherxStatus: verdict.status,
                riskScore: verdict.riskScore,
                confidence: verdict.confidence,
                isCorrect,
                indicators: (verdict.indicators || []).map(i => ({
                    type: i.type,
                    severity: i.severity,
                    score: i.score,
                    message: i.message
                })),
                reasons: verdict.reasons || []
            });
        }
    } finally {
        axios.post = originalAxiosPost;
    }

    // Calculate core statistics
    const cm = calculateConfusionMatrix(evaluatedResults);
    const metrics = calculateMetrics(cm);
    const thresholdAnalysis = evaluateThresholds(evaluatedResults, [30, 40, 50, 60, 70, 80]);
    const categoryBreakdown = breakdownByCategory(evaluatedResults);

    // Extract false alarms and missed threats
    const falsePositives = evaluatedResults.filter(r => r.groundTruth === 'BENIGN' && r.predictedLabel === 'MALICIOUS');
    const falseNegatives = evaluatedResults.filter(r => r.groundTruth === 'MALICIOUS' && r.predictedLabel === 'BENIGN');

    const benchmarkReport = {
        timestamp: new Date().toISOString(),
        datasetInfo: {
            name: 'CypherX Curated Seed Benchmark',
            type: 'CURATED_SEED_DATASET',
            totalSamples: evaluatedResults.length,
            benignSamples: benignData.length,
            maliciousSamples: maliciousData.length
        },
        confusionMatrix: cm,
        metrics,
        thresholdAnalysis,
        categoryBreakdown,
        falsePositives,
        falseNegatives
    };

    // Save machine-readable output if configured
    if (saveResults) {
        const resultsDir = path.join(__dirname, 'results');
        if (!fs.existsSync(resultsDir)) {
            fs.mkdirSync(resultsDir, { recursive: true });
        }
        const outputPath = path.join(resultsDir, 'latest.json');
        fs.writeFileSync(outputPath, JSON.stringify(benchmarkReport, null, 2), 'utf8');
    }

    return benchmarkReport;
}

/**
 * Pretty-print terminal benchmark report
 */
function printTerminalReport(report) {
    const { datasetInfo, confusionMatrix: cm, metrics, thresholdAnalysis, categoryBreakdown, falsePositives, falseNegatives } = report;

    console.log('\n══════════════════════════════════════════════════════════════');
    console.log('             CypherX Detection Engine Benchmark                ');
    console.log('══════════════════════════════════════════════════════════════\n');

    console.log(`Dataset:      ${datasetInfo.name} [${datasetInfo.type}]`);
    console.log(`Total Count:  ${datasetInfo.totalSamples} samples (${datasetInfo.benignSamples} Benign, ${datasetInfo.maliciousSamples} Malicious)\n`);

    console.log('──────────────────────────────────────────────────────────────');
    console.log('Confusion Matrix:');
    console.log('                              Predicted');
    console.log('                       BENIGN        MALICIOUS');
    console.log(`  Actual BENIGN        ${String(cm.tn).padStart(6)} (TN)    ${String(cm.fp).padStart(9)} (FP)`);
    console.log(`  Actual MALICIOUS     ${String(cm.fn).padStart(6)} (FN)    ${String(cm.tp).padStart(9)} (TP)\n`);

    console.log('──────────────────────────────────────────────────────────────');
    console.log('Core Security Performance Metrics:');
    console.log(`  Accuracy:             ${metrics.accuracy.toFixed(1)}%`);
    console.log(`  Precision:            ${metrics.precision.toFixed(1)}%  (Of all flagged threats, % truly malicious)`);
    console.log(`  Recall (Sensitivity): ${metrics.recall.toFixed(1)}%  (Of all true threats, % detected)`);
    console.log(`  F1 Score:             ${metrics.f1Score.toFixed(1)}%  (Harmonic mean of Precision & Recall)`);
    console.log(`  False Positive Rate:  ${metrics.falsePositiveRate.toFixed(1)}%  (Legitimate sites incorrectly flagged)`);
    console.log(`  False Negative Rate:  ${metrics.falseNegativeRate.toFixed(1)}%  (Malicious sites missed by engine)\n`);

    console.log('──────────────────────────────────────────────────────────────');
    console.log('Threshold Sensitivity Analysis (Risk Score Thresholds):');
    console.log('  Score Threshold │ Precision │  Recall  │ F1 Score │ (TP / FP / FN)');
    console.log('  ────────────────┼───────────┼──────────┼──────────┼───────────────');
    for (const t of thresholdAnalysis) {
        console.log(`  Score >= ${String(t.threshold).padEnd(5)} │   ${String(t.precision.toFixed(1) + '%').padStart(6)}  │  ${String(t.recall.toFixed(1) + '%').padStart(6)}  │  ${String(t.f1Score.toFixed(1) + '%').padStart(6)}  │ (${t.tp} / ${t.fp} / ${t.fn})`);
    }
    console.log('');

    console.log('──────────────────────────────────────────────────────────────');
    console.log('Category Performance Breakdown:');
    console.log('  Category                          │ Samples │ Ground Truth │ Accuracy');
    console.log('  ──────────────────────────────────┼─────────┼──────────────┼─────────');
    for (const [cat, data] of Object.entries(categoryBreakdown)) {
        const catName = cat.length > 32 ? cat.substring(0, 29) + '...' : cat.padEnd(32);
        const samples = String(data.samples).padStart(7);
        const truth = data.groundTruth.padEnd(12);
        const acc = String(data.accuracy.toFixed(1) + '%').padStart(8);
        console.log(`  ${catName}  │ ${samples} │ ${truth} │ ${acc}`);
    }
    console.log('');

    if (falsePositives.length > 0) {
        console.log('──────────────────────────────────────────────────────────────');
        console.log(`⚠️ FALSE POSITIVES (${falsePositives.length}):`);
        for (const fp of falsePositives) {
            console.log(`  • URL:    ${fp.url}`);
            console.log(`    Status: ${fp.cypherxStatus} (Score: ${fp.riskScore})`);
            console.log(`    Reasons: ${fp.reasons.join(', ')}`);
        }
        console.log('');
    } else {
        console.log('──────────────────────────────────────────────────────────────');
        console.log('✅ FALSE POSITIVES: 0 (No legitimate URLs were falsely flagged)\n');
    }

    if (falseNegatives.length > 0) {
        console.log('──────────────────────────────────────────────────────────────');
        console.log(`⚠️ FALSE NEGATIVES (${falseNegatives.length}):`);
        for (const fn of falseNegatives) {
            console.log(`  • URL:    ${fn.url}`);
            console.log(`    Status: ${fn.cypherxStatus} (Score: ${fn.riskScore})`);
            console.log(`    Reasons: ${fn.reasons.join(', ') || 'No indicators detected'}`);
        }
        console.log('');
    } else {
        console.log('──────────────────────────────────────────────────────────────');
        console.log('✅ FALSE NEGATIVES: 0 (All seed threat patterns detected)\n');
    }

    console.log('══════════════════════════════════════════════════════════════');
    console.log('  Note: Results reflect CURATED_SEED_DATASET heuristics check.');
    console.log('  Does NOT represent production-scale real-world distribution.');
    console.log('══════════════════════════════════════════════════════════════\n');
}

// Direct execution entrypoint
if (require.main === module) {
    runBenchmark()
        .then(report => {
            printTerminalReport(report);
        })
        .catch(err => {
            console.error('Benchmark execution error:', err.message);
            process.exit(1);
        });
}

module.exports = {
    loadDataset,
    runBenchmark,
    printTerminalReport
};
