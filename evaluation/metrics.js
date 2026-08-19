/**
 * Statistical Metrics Engine for CypherX Evaluation Benchmark
 */

/**
 * Compute standard confusion matrix from evaluation results
 * 
 * @param {Array<Object>} results Array of evaluated item results
 * @returns {Object} { tp, tn, fp, fn, total }
 */
function calculateConfusionMatrix(results = []) {
    let tp = 0; // Actual MALICIOUS, Predicted MALICIOUS
    let tn = 0; // Actual BENIGN, Predicted BENIGN
    let fp = 0; // Actual BENIGN, Predicted MALICIOUS (False Alarm)
    let fn = 0; // Actual MALICIOUS, Predicted BENIGN (Missed Threat)

    for (const item of results) {
        const actual = item.groundTruth;
        const predicted = item.predictedLabel;

        if (actual === 'MALICIOUS') {
            if (predicted === 'MALICIOUS') tp++;
            else fn++;
        } else if (actual === 'BENIGN') {
            if (predicted === 'BENIGN') tn++;
            else fp++;
        }
    }

    return {
        tp,
        tn,
        fp,
        fn,
        total: results.length
    };
}

/**
 * Calculate standard classification metrics from confusion matrix
 * 
 * @param {Object} cm Confusion matrix object
 * @returns {Object} Metric percentages (0 - 100) and raw rates (0 - 1)
 */
function calculateMetrics(cm) {
    const { tp, tn, fp, fn, total } = cm;

    if (total === 0) {
        return {
            accuracy: 0,
            precision: 0,
            recall: 0,
            specificity: 0,
            f1Score: 0,
            falsePositiveRate: 0,
            falseNegativeRate: 0
        };
    }

    const accuracy = (tp + tn) / total;
    const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
    const specificity = (tn + fp) > 0 ? tn / (tn + fp) : 0;
    const f1Score = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const falsePositiveRate = (fp + tn) > 0 ? fp / (fp + tn) : 0;
    const falseNegativeRate = (tp + fn) > 0 ? fn / (tp + fn) : 0;

    return {
        accuracy: Number((accuracy * 100).toFixed(1)),
        precision: Number((precision * 100).toFixed(1)),
        recall: Number((recall * 100).toFixed(1)),
        specificity: Number((specificity * 100).toFixed(1)),
        f1Score: Number((f1Score * 100).toFixed(1)),
        falsePositiveRate: Number((falsePositiveRate * 100).toFixed(1)),
        falseNegativeRate: Number((falseNegativeRate * 100).toFixed(1))
    };
}

/**
 * Run parametric threshold sweep analysis across risk scores (0 - 100)
 * 
 * @param {Array<Object>} results
 * @param {Array<number>} thresholds
 * @returns {Array<Object>}
 */
function evaluateThresholds(results = [], thresholds = [30, 40, 50, 60, 70, 80]) {
    return thresholds.map(threshold => {
        const thresholdResults = results.map(r => ({
            ...r,
            predictedLabel: r.riskScore >= threshold ? 'MALICIOUS' : 'BENIGN'
        }));

        const cm = calculateConfusionMatrix(thresholdResults);
        const metrics = calculateMetrics(cm);

        return {
            threshold,
            tp: cm.tp,
            fp: cm.fp,
            fn: cm.fn,
            tn: cm.tn,
            precision: metrics.precision,
            recall: metrics.recall,
            f1Score: metrics.f1Score
        };
    });
}

/**
 * Group results by category and evaluate category-specific recall / accuracy
 * 
 * @param {Array<Object>} results
 * @returns {Object}
 */
function breakdownByCategory(results = []) {
    const categories = {};

    for (const item of results) {
        const cat = item.category || 'uncategorized';
        if (!categories[cat]) {
            categories[cat] = {
                category: cat,
                total: 0,
                correct: 0,
                label: item.groundTruth
            };
        }

        categories[cat].total++;
        if (item.isCorrect) {
            categories[cat].correct++;
        }
    }

    const summary = {};
    for (const [key, data] of Object.entries(categories)) {
        summary[key] = {
            category: key,
            samples: data.total,
            groundTruth: data.label,
            correct: data.correct,
            accuracy: data.total > 0 ? Number(((data.correct / data.total) * 100).toFixed(1)) : 0
        };
    }

    return summary;
}

module.exports = {
    calculateConfusionMatrix,
    calculateMetrics,
    evaluateThresholds,
    breakdownByCategory
};
