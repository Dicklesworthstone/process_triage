//! DuckDB query generation for calibration analysis.
//!
//! Generates SQL queries for analyzing signature match calibration data
//! stored in Parquet telemetry files.

/// Generate a DuckDB query for computing overall calibration metrics.
pub fn overall_calibration_query(parquet_path: &str) -> String {
    format!(
        r#"
-- Overall Calibration Metrics
-- Requires: DuckDB with Parquet support
-- Usage: duckdb -c "$(cat this_query.sql)"

WITH matches AS (
    SELECT
        signature_id,
        signature_category,
        match_confidence,
        predicted_prob_abandoned,
        actual_abandoned,
        human_decision
    FROM read_parquet('{parquet_path}')
    WHERE outcome_available = true
),
calibration AS (
    SELECT
        COUNT(*) as n,
        AVG(predicted_prob_abandoned) as mean_predicted,
        AVG(CAST(actual_abandoned AS DOUBLE)) as actual_rate,
        AVG(predicted_prob_abandoned) - AVG(CAST(actual_abandoned AS DOUBLE)) as bias,
        -- Brier score
        AVG(POWER(predicted_prob_abandoned - CAST(actual_abandoned AS DOUBLE), 2)) as brier_score,
        -- Log loss (with epsilon to avoid log(0))
        -AVG(
            CASE
                WHEN actual_abandoned THEN LN(GREATEST(predicted_prob_abandoned, 1e-15))
                ELSE LN(GREATEST(1 - predicted_prob_abandoned, 1e-15))
            END
        ) as log_loss
    FROM matches
)
SELECT
    n as sample_count,
    ROUND(mean_predicted, 4) as mean_predicted,
    ROUND(actual_rate, 4) as actual_positive_rate,
    ROUND(bias, 4) as calibration_bias,
    ROUND(brier_score, 4) as brier_score,
    ROUND(log_loss, 4) as log_loss,
    CASE
        WHEN ABS(bias) < 0.05 THEN 'Well calibrated'
        WHEN bias > 0.1 THEN 'Overconfident'
        WHEN bias < -0.1 THEN 'Underconfident'
        ELSE 'Minor bias'
    END as calibration_assessment
FROM calibration;
"#,
        parquet_path = parquet_path
    )
}

/// Generate a DuckDB query for calibration by signature category.
pub fn calibration_by_category_query(parquet_path: &str) -> String {
    format!(
        r#"
-- Calibration Metrics by Signature Category
WITH matches AS (
    SELECT *
    FROM read_parquet('{parquet_path}')
    WHERE outcome_available = true
)
SELECT
    signature_category,
    COUNT(*) as n,
    ROUND(AVG(match_confidence), 3) as mean_confidence,
    ROUND(AVG(predicted_prob_abandoned), 3) as mean_predicted,
    ROUND(AVG(CAST(actual_abandoned AS DOUBLE)), 3) as actual_rate,
    ROUND(AVG(predicted_prob_abandoned) - AVG(CAST(actual_abandoned AS DOUBLE)), 3) as bias,
    ROUND(AVG(POWER(predicted_prob_abandoned - CAST(actual_abandoned AS DOUBLE), 2)), 4) as brier,
    -- Confusion matrix components (at 0.5 threshold)
    SUM(CASE WHEN predicted_prob_abandoned >= 0.5 AND actual_abandoned THEN 1 ELSE 0 END) as TP,
    SUM(CASE WHEN predicted_prob_abandoned >= 0.5 AND NOT actual_abandoned THEN 1 ELSE 0 END) as FP,
    SUM(CASE WHEN predicted_prob_abandoned < 0.5 AND actual_abandoned THEN 1 ELSE 0 END) as FN,
    SUM(CASE WHEN predicted_prob_abandoned < 0.5 AND NOT actual_abandoned THEN 1 ELSE 0 END) as TN
FROM matches
GROUP BY signature_category
HAVING COUNT(*) >= 10
ORDER BY n DESC;
"#,
        parquet_path = parquet_path
    )
}

/// Generate a DuckDB query for calibration by individual signature.
pub fn calibration_by_signature_query(parquet_path: &str, min_samples: usize) -> String {
    format!(
        r#"
-- Calibration Metrics by Individual Signature
WITH matches AS (
    SELECT *
    FROM read_parquet('{parquet_path}')
    WHERE outcome_available = true
),
signature_stats AS (
    SELECT
        signature_id,
        signature_category,
        COUNT(*) as n,
        AVG(match_confidence) as mean_confidence,
        AVG(predicted_prob_abandoned) as mean_predicted,
        AVG(CAST(actual_abandoned AS DOUBLE)) as actual_rate,
        AVG(POWER(predicted_prob_abandoned - CAST(actual_abandoned AS DOUBLE), 2)) as brier,
        -- Precision and recall
        SUM(CASE WHEN predicted_prob_abandoned >= 0.5 AND actual_abandoned THEN 1 ELSE 0 END) as TP,
        SUM(CASE WHEN predicted_prob_abandoned >= 0.5 AND NOT actual_abandoned THEN 1 ELSE 0 END) as FP,
        SUM(CASE WHEN predicted_prob_abandoned < 0.5 AND actual_abandoned THEN 1 ELSE 0 END) as FN
    FROM matches
    GROUP BY signature_id, signature_category
    HAVING COUNT(*) >= {min_samples}
)
SELECT
    signature_id,
    signature_category,
    n,
    ROUND(mean_confidence, 3) as mean_confidence,
    ROUND(mean_predicted, 3) as mean_predicted,
    ROUND(actual_rate, 3) as actual_rate,
    ROUND(mean_predicted - actual_rate, 3) as bias,
    ROUND(brier, 4) as brier_score,
    ROUND(CASE WHEN TP + FP > 0 THEN TP::DOUBLE / (TP + FP) ELSE 0 END, 3) as precision,
    ROUND(CASE WHEN TP + FN > 0 THEN TP::DOUBLE / (TP + FN) ELSE 0 END, 3) as recall,
    CASE
        WHEN ABS(mean_predicted - actual_rate) > 0.2 THEN 'NEEDS REVIEW'
        WHEN brier > 0.25 THEN 'Poor'
        WHEN brier > 0.15 THEN 'Fair'
        ELSE 'Good'
    END as status
FROM signature_stats
ORDER BY n DESC, brier DESC;
"#,
        parquet_path = parquet_path,
        min_samples = min_samples
    )
}

/// Generate a DuckDB query for reliability diagram bins.
pub fn reliability_diagram_query(parquet_path: &str, num_bins: usize) -> String {
    format!(
        r#"
-- Reliability Diagram Data (Calibration Curve)
WITH matches AS (
    SELECT
        predicted_prob_abandoned as pred,
        CAST(actual_abandoned AS DOUBLE) as actual
    FROM read_parquet('{parquet_path}')
    WHERE outcome_available = true
),
binned AS (
    SELECT
        FLOOR(pred * {num_bins}) as bin_idx,
        pred,
        actual
    FROM matches
)
SELECT
    bin_idx,
    ROUND(bin_idx::DOUBLE / {num_bins}, 2) as bin_lower,
    ROUND((bin_idx + 1)::DOUBLE / {num_bins}, 2) as bin_upper,
    COUNT(*) as n,
    ROUND(AVG(pred), 4) as mean_predicted,
    ROUND(AVG(actual), 4) as actual_rate,
    ROUND(AVG(pred) - AVG(actual), 4) as bin_error
FROM binned
GROUP BY bin_idx
ORDER BY bin_idx;
"#,
        parquet_path = parquet_path,
        num_bins = num_bins
    )
}

/// Generate a DuckDB query for threshold analysis.
pub fn threshold_analysis_query(parquet_path: &str) -> String {
    format!(
        r#"
-- Threshold Analysis: Metrics at Different Decision Thresholds
WITH matches AS (
    SELECT
        predicted_prob_abandoned as pred,
        actual_abandoned as actual
    FROM read_parquet('{parquet_path}')
    WHERE outcome_available = true
),
thresholds AS (
    SELECT unnest(ARRAY[0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]) as threshold
),
metrics AS (
    SELECT
        t.threshold,
        COUNT(*) as n,
        SUM(CASE WHEN pred >= t.threshold AND actual THEN 1 ELSE 0 END) as TP,
        SUM(CASE WHEN pred >= t.threshold AND NOT actual THEN 1 ELSE 0 END) as FP,
        SUM(CASE WHEN pred < t.threshold AND actual THEN 1 ELSE 0 END) as FN,
        SUM(CASE WHEN pred < t.threshold AND NOT actual THEN 1 ELSE 0 END) as TN
    FROM matches, thresholds t
    GROUP BY t.threshold
)
SELECT
    threshold,
    n as total,
    TP, FP, FN, TN,
    ROUND(CASE WHEN TP + FP > 0 THEN TP::DOUBLE / (TP + FP) ELSE 0 END, 3) as precision,
    ROUND(CASE WHEN TP + FN > 0 THEN TP::DOUBLE / (TP + FN) ELSE 0 END, 3) as recall,
    ROUND(CASE WHEN TP + FP > 0 AND TP + FN > 0
        THEN 2.0 * (TP::DOUBLE / (TP + FP)) * (TP::DOUBLE / (TP + FN)) /
             ((TP::DOUBLE / (TP + FP)) + (TP::DOUBLE / (TP + FN)))
        ELSE 0 END, 3) as f1,
    ROUND((TP + TN)::DOUBLE / n, 3) as accuracy
FROM metrics
ORDER BY threshold;
"#,
        parquet_path = parquet_path
    )
}

/// Generate a DuckDB query for problematic signatures (high error rate).
pub fn problematic_signatures_query(parquet_path: &str, min_samples: usize) -> String {
    format!(
        r#"
-- Problematic Signatures: High Calibration Error
WITH matches AS (
    SELECT *
    FROM read_parquet('{parquet_path}')
    WHERE outcome_available = true
),
signature_stats AS (
    SELECT
        signature_id,
        signature_category,
        COUNT(*) as n,
        AVG(predicted_prob_abandoned) as mean_pred,
        AVG(CAST(actual_abandoned AS DOUBLE)) as actual_rate,
        AVG(POWER(predicted_prob_abandoned - CAST(actual_abandoned AS DOUBLE), 2)) as brier,
        -- Track what went wrong
        SUM(CASE WHEN predicted_prob_abandoned >= 0.5 AND NOT actual_abandoned THEN 1 ELSE 0 END) as false_positives,
        SUM(CASE WHEN predicted_prob_abandoned < 0.5 AND actual_abandoned THEN 1 ELSE 0 END) as false_negatives
    FROM matches
    GROUP BY signature_id, signature_category
    HAVING COUNT(*) >= {min_samples}
)
SELECT
    signature_id,
    signature_category,
    n as sample_count,
    ROUND(mean_pred, 3) as mean_predicted,
    ROUND(actual_rate, 3) as actual_rate,
    ROUND(mean_pred - actual_rate, 3) as bias,
    ROUND(brier, 4) as brier_score,
    false_positives as FP,
    false_negatives as FN,
    CASE
        WHEN mean_pred - actual_rate > 0.2 THEN 'Overconfident - lower threshold'
        WHEN mean_pred - actual_rate < -0.2 THEN 'Underconfident - raise threshold'
        WHEN false_positives > false_negatives * 2 THEN 'Too aggressive'
        WHEN false_negatives > false_positives * 2 THEN 'Too conservative'
        ELSE 'Review manually'
    END as recommendation
FROM signature_stats
WHERE ABS(mean_pred - actual_rate) > 0.15 OR brier > 0.20
ORDER BY brier DESC, n DESC;
"#,
        parquet_path = parquet_path,
        min_samples = min_samples
    )
}

/// Generate all calibration queries as a single SQL file.
pub fn all_calibration_queries(parquet_path: &str) -> String {
    let mut output = String::new();

    output.push_str("-- =================================================================\n");
    output.push_str("-- SIGNATURE CALIBRATION ANALYSIS QUERIES\n");
    output.push_str("-- Generated by pt-core calibration module\n");
    output.push_str("-- =================================================================\n\n");

    output.push_str("-- Section 1: Overall Calibration\n");
    output.push_str(&overall_calibration_query(parquet_path));
    output.push_str("\n\n");

    output.push_str("-- Section 2: Calibration by Category\n");
    output.push_str(&calibration_by_category_query(parquet_path));
    output.push_str("\n\n");

    output.push_str("-- Section 3: Calibration by Signature\n");
    output.push_str(&calibration_by_signature_query(parquet_path, 10));
    output.push_str("\n\n");

    output.push_str("-- Section 4: Reliability Diagram\n");
    output.push_str(&reliability_diagram_query(parquet_path, 10));
    output.push_str("\n\n");

    output.push_str("-- Section 5: Threshold Analysis\n");
    output.push_str(&threshold_analysis_query(parquet_path));
    output.push_str("\n\n");

    output.push_str("-- Section 6: Problematic Signatures\n");
    output.push_str(&problematic_signatures_query(parquet_path, 10));

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overall_calibration_query() {
        let query = overall_calibration_query("test.parquet");
        assert!(query.contains("brier_score"));
        assert!(query.contains("test.parquet"));
        assert!(query.contains("log_loss"));
    }

    #[test]
    fn test_calibration_by_category_query() {
        let query = calibration_by_category_query("test.parquet");
        assert!(query.contains("signature_category"));
        assert!(query.contains("GROUP BY"));
    }

    #[test]
    fn test_reliability_diagram_query() {
        let query = reliability_diagram_query("test.parquet", 10);
        assert!(query.contains("bin_idx"));
        assert!(query.contains("mean_predicted"));
        assert!(query.contains("actual_rate"));
    }

    #[test]
    fn test_threshold_analysis_query() {
        let query = threshold_analysis_query("test.parquet");
        assert!(query.contains("precision"));
        assert!(query.contains("recall"));
        assert!(query.contains("f1"));
    }

    #[test]
    fn test_problematic_signatures_query() {
        let query = problematic_signatures_query("test.parquet", 20);
        assert!(query.contains("false_positives"));
        assert!(query.contains("recommendation"));
        assert!(query.contains("20")); // min_samples
    }

    #[test]
    fn test_all_queries_combined() {
        let combined = all_calibration_queries("data.parquet");
        assert!(combined.contains("Section 1"));
        assert!(combined.contains("Section 6"));
        assert!(combined.contains("data.parquet"));
    }
}
