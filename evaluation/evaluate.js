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
const { createBalancedDataset, createDatasetSplits } = require('./ingestion/dataQuality');

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
    const mode = options.mode || 'real'; // 'seed' or 'real'
    const split = options.split || 'all'; // 'all', 'development', 'validation', 'test'
    const balanced = options.balanced !== false; // default true for 50/50 comparison
    const saveResults = options.saveResults !== false;

    let benignPath;
    let maliciousPath;
    let metadataPath;
    let datasetName;
    let datasetType;

    if (mode === 'seed') {
        const seedBenign = path.join(__dirname, 'datasets/seed/benign.json');
        const fallbackBenign = path.join(__dirname, 'datasets/benign.json');
        benignPath = fs.existsSync(seedBenign) ? seedBenign : fallbackBenign;

        const seedMalicious = path.join(__dirname, 'datasets/seed/malicious.json');
        const fallbackMalicious = path.join(__dirname, 'datasets/malicious.json');
        maliciousPath = fs.existsSync(seedMalicious) ? seedMalicious : fallbackMalicious;

        datasetName = 'CypherX Curated Seed Benchmark';
        datasetType = 'CURATED_SEED_DATASET';
    } else {
        benignPath = path.join(__dirname, 'datasets/real-world/benign.json');
        maliciousPath = path.join(__dirname, 'datasets/real-world/malicious.json');
        metadataPath = path.join(__dirname, 'datasets/real-world/metadata.json');

        datasetName = 'CypherX Real-World Security Benchmark';
        datasetType = 'REAL_WORLD_BENCHMARK';
    }

    // Load ground-truth datasets
    const benignData = loadDataset(benignPath);
    const maliciousData = loadDataset(maliciousPath);
    let fullDataset = [...benignData, ...maliciousData];

    // Load quality metadata if available
    let datasetMetadata = null;
    if (metadataPath && fs.existsSync(metadataPath)) {
        datasetMetadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    }

    // Apply partition split if requested
    if (split !== 'all' && mode === 'real') {
        const splits = createDatasetSplits(fullDataset);
        if (splits[split]) {
            fullDataset = splits[split];
        }
    }

    // Apply balancing if requested
    if (balanced) {
        fullDataset = createBalancedDataset(fullDataset);
    }

    // Mock Google Safe Browsing to ensure 100% deterministic, hermetic benchmarking
    const originalAxiosPost = axios.post;
    axios.post = async () => ({
        data: { matches: [] } // Deterministic clean baseline (evaluates local static heuristics)
    });

    const evaluatedResults = [];

    try {
        for (const item of fullDataset) {
            const verdict = await scanUrl(item.url, 'Evaluation Benchmark');
            
            // Binary prediction mapping
            // SUSPICIOUS and DANGEROUS map to MALICIOUS
            // SAFE and UNVERIFIED map to BENIGN
            const predictedLabel = (verdict.status === 'SUSPICIOUS' || verdict.status === 'DANGEROUS') 
                ? 'MALICIOUS' 
                : 'BENIGN';

            const isCorrect = item.label === predictedLabel;

            evaluatedResults.push({
                url: item.url,
                category: item.category || 'unknown',
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

    // Extract and sort errors for deep inspection
    // False Positives: Benign flagged as Malicious (sorted by highest risk score first)
    const falsePositives = evaluatedResults
        .filter(r => r.groundTruth === 'BENIGN' && r.predictedLabel === 'MALICIOUS')
        .sort((a, b) => b.riskScore - a.riskScore);

    // False Negatives: Malicious missed as Benign (sorted by lowest risk score first)
    const falseNegatives = evaluatedResults
        .filter(r => r.groundTruth === 'MALICIOUS' && r.predictedLabel === 'BENIGN')
        .sort((a, b) => a.riskScore - b.riskScore);

    const actualBenign = evaluatedResults.filter(r => r.groundTruth === 'BENIGN').length;
    const actualMalicious = evaluatedResults.filter(r => r.groundTruth === 'MALICIOUS').length;

    const benchmarkReport = {
        timestamp: new Date().toISOString(),
        datasetInfo: {
            name: datasetName,
            type: datasetType,
            mode,
            split,
            balanced,
            totalSamples: evaluatedResults.length,
            benignSamples: actualBenign,
            maliciousSamples: actualMalicious,
            qualityReport: datasetMetadata ? datasetMetadata.qualityReport : null
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
        
        const fileName = mode === 'seed' ? 'seed-latest.json' : 'real-world-latest.json';
        fs.writeFileSync(path.join(resultsDir, fileName), JSON.stringify(benchmarkReport, null, 2), 'utf8');
        fs.writeFileSync(path.join(resultsDir, 'latest.json'), JSON.stringify(benchmarkReport, null, 2), 'utf8');
    }

    return benchmarkReport;
}

/**
 * Pretty-print terminal benchmark report
 */
function printTerminalReport(report) {
    const { datasetInfo, confusionMatrix: cm, metrics, thresholdAnalysis, categoryBreakdown, falsePositives, falseNegatives } = report;

    console.log('\n══════════════════════════════════════════════════════════════');
    console.log(`             ${datasetInfo.name}                `);
    console.log('══════════════════════════════════════════════════════════════\n');

    console.log(`Dataset:      ${datasetInfo.name} [${datasetInfo.type}]`);
    console.log(`Config:       Mode=${datasetInfo.mode.toUpperCase()} | Split=${datasetInfo.split} | Balanced=${datasetInfo.balanced}`);
    console.log(`Total Count:  ${datasetInfo.totalSamples} samples (${datasetInfo.benignSamples} Benign, ${datasetInfo.maliciousSamples} Malicious)\n`);

    if (datasetInfo.qualityReport) {
        const qr = datasetInfo.qualityReport;
        console.log('──────────────────────────────────────────────────────────────');
        console.log('Data Quality & Provenance Summary:');
        console.log(`  • Raw Imported:      ${qr.imported}`);
        console.log(`  • Valid & Parsed:    ${qr.valid}`);
        console.log(`  • Invalid Filtered:  ${qr.invalid}`);
        console.log(`  • Duplicates Merged: ${qr.duplicatesRemoved}`);
        console.log(`  • Conflicts Excluded:${qr.conflictsExcluded}`);
        console.log(`  • Source Feeds:      ${Object.entries(qr.sourceDistribution).map(([k, v]) => `${k} (${v})`).join(', ')}`);
        if (qr.temporalCoverage && qr.temporalCoverage.earliestDate) {
            console.log(`  • Date Range:        ${qr.temporalCoverage.earliestDate.split('T')[0]} to ${qr.temporalCoverage.latestDate.split('T')[0]}`);
        }
        console.log('');
    }

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
    console.log('Threshold Sensitivity Analysis (Risk Score Cutoffs):');
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
        console.log(`⚠️ TOP FALSE POSITIVES (${falsePositives.length} total, displaying up to 5):`);
        for (const fp of falsePositives.slice(0, 5)) {
            console.log(`  • URL:    ${fp.url}`);
            console.log(`    Status: ${fp.cypherxStatus} (Score: ${fp.riskScore}) | Source: ${fp.source}`);
            console.log(`    Reasons: ${fp.reasons.join(', ')}`);
        }
        console.log('');
    } else {
        console.log('──────────────────────────────────────────────────────────────');
        console.log('✅ FALSE POSITIVES: 0 (No legitimate URLs were falsely flagged)\n');
    }

    if (falseNegatives.length > 0) {
        console.log('──────────────────────────────────────────────────────────────');
        console.log(`⚠️ TOP FALSE NEGATIVES (${falseNegatives.length} total, displaying up to 5 lowest scores):`);
        for (const fn of falseNegatives.slice(0, 5)) {
            console.log(`  • URL:    ${fn.url}`);
            console.log(`    Status: ${fn.cypherxStatus} (Score: ${fn.riskScore}) | Source: ${fn.source} | Cat: ${fn.category}`);
            console.log(`    Reasons: ${fn.reasons.join(', ') || 'No heuristic indicators fired'}`);
        }
        console.log('');
    } else {
        console.log('──────────────────────────────────────────────────────────────');
        console.log('✅ FALSE NEGATIVES: 0 (All threat patterns detected)\n');
    }

    console.log('══════════════════════════════════════════════════════════════');
    if (datasetInfo.type === 'CURATED_SEED_DATASET') {
        console.log('  Note: Results reflect CURATED_SEED_DATASET heuristics check.');
    } else {
        console.log('  Note: Results evaluate static heuristic performance on');
        console.log('  reputable external feeds (Tranco, OpenPhish, PhishTank, URLhaus).');
    }
    console.log('══════════════════════════════════════════════════════════════\n');
}

// CLI argument parsing
if (require.main === module) {
    const args = process.argv.slice(2);
    let mode = 'real';
    let split = 'all';
    let balanced = true;

    for (const arg of args) {
        if (arg.startsWith('--mode=')) mode = arg.split('=')[1];
        if (arg.startsWith('--split=')) split = arg.split('=')[1];
        if (arg === '--seed') mode = 'seed';
        if (arg === '--real') mode = 'real';
        if (arg === '--unbalanced') balanced = false;
    }

    runBenchmark({ mode, split, balanced })
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
