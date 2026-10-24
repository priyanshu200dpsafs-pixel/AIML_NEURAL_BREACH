#!/usr/bin/env python3
"""
Metrics Engine — Unified Ground-Truth Evaluation Module
Team: Neural Breach | AI/ML Cyber Defense Platform
Role 3: Machine Learning & Reliability Specialist

Derives all evaluation metrics from a single source of truth (y_true, y_pred, y_proba).
Implements mathematical consistency assertions, cybersecurity SOC metrics (FPR, FNR,
attack detection rate, missed attacks), and Wilson score confidence intervals for rare attacks.
"""

import math
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix


def wilson_score_interval(successes: int, trials: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Computes Wilson score confidence interval for binomial proportion.
    Essential for rare cyber attack classes with small sample support (e.g. SQLi N=15, XSS N=37).
    """
    if trials == 0:
        return (0.0, 0.0)
    
    # 1.96 for 95% confidence
    z = 1.959963984540054
    p = successes / trials
    denominator = 1 + z**2 / trials
    centre_adjusted_probability = p + z**2 / (2 * trials)
    adjusted_standard_deviation = math.sqrt((p * (1 - p) + z**2 / (4 * trials)) / trials)
    
    lower_bound = (centre_adjusted_probability - z * adjusted_standard_deviation) / denominator
    upper_bound = (centre_adjusted_probability + z * adjusted_standard_deviation) / denominator
    return (max(0.0, float(lower_bound)), min(1.0, float(upper_bound)))


def evaluate_cyber_detection_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    label_mapping: Dict[int, str],
    y_proba: Optional[np.ndarray] = None,
    benign_class_name: str = "Benign"
) -> Dict[str, Any]:
    """
    Derives all cyber defense evaluation metrics from single source of truth arrays.
    Enforces automated mathematical consistency checks across confusion matrix,
    supports, false alarms, and missed attacks.
    """
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    n_samples = len(y_true)
    
    if len(y_pred) != n_samples:
        raise ValueError(f"Shape mismatch: y_true ({n_samples}) vs y_pred ({len(y_pred)})")

    # Locate Benign class index
    benign_indices = [idx for idx, name in label_mapping.items() if name == benign_class_name]
    if not benign_indices:
        raise ValueError(f"Benign class '{benign_class_name}' not found in label_mapping: {label_mapping}")
    benign_idx = benign_indices[0]
    attack_indices = [idx for idx in label_mapping.keys() if idx != benign_idx]

    # Global multi-class metrics
    acc = float(accuracy_score(y_true, y_pred))
    num_classes = len(label_mapping)
    all_class_indices = sorted(list(label_mapping.keys()))
    
    prec, rec, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=all_class_indices, zero_division=0
    )
    
    macro_f1 = float(np.mean(f1))
    weighted_f1 = float(np.sum(f1 * support) / n_samples)
    
    # Confusion matrix: cm[true_class, pred_class]
    cm = confusion_matrix(y_true, y_pred, labels=all_class_indices)
    
    # -------------------------------------------------------------
    # Mathematical Consistency Assertions
    # -------------------------------------------------------------
    assert cm.sum() == n_samples, f"CM sum {cm.sum()} != total samples {n_samples}"
    assert np.all(cm.sum(axis=1) == support), "Row sums of CM do not match class support"

    # Benign metrics (False Positives / False Alarms)
    total_benign = int(support[benign_idx])
    true_benign = int(cm[benign_idx, benign_idx])
    false_positives = int(cm[benign_idx].sum() - true_benign)
    benign_fpr = float(false_positives / total_benign) if total_benign > 0 else 0.0
    benign_specificity = float(true_benign / total_benign) if total_benign > 0 else 0.0

    # Attack metrics (Missed Attacks / False Negatives to Benign)
    total_attacks = int(sum(support[i] for i in attack_indices))
    
    # A true missed attack is an attack predicted as BENIGN
    missed_attacks_by_class = {
        label_mapping[i]: int(cm[i, benign_idx]) for i in attack_indices
    }
    total_missed_attacks = int(sum(missed_attacks_by_class.values()))
    attack_fnr = float(total_missed_attacks / total_attacks) if total_attacks > 0 else 0.0
    attack_detection_rate = float(1.0 - attack_fnr) if total_attacks > 0 else 0.0

    # Verification: Attacks that triggered ANY attack alert
    attacks_alerted = int(sum(cm[i, j] for i in attack_indices for j in attack_indices))
    assert attacks_alerted + total_missed_attacks == total_attacks, (
        f"Attacks alerted ({attacks_alerted}) + missed ({total_missed_attacks}) != total attacks ({total_attacks})"
    )

    # Per-class detailed breakdown
    per_class_metrics = {}
    for i, class_name in label_mapping.items():
        tp = int(cm[i, i])
        fn = int(cm[i].sum() - tp)
        fp = int(cm[:, i].sum() - tp)
        sup = int(support[i])
        
        recall_ci = wilson_score_interval(tp, sup) if sup > 0 else (0.0, 0.0)
        
        per_class_metrics[class_name] = {
            "class_index": int(i),
            "support": sup,
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "precision": float(prec[i]),
            "recall": float(rec[i]),
            "f1_score": float(f1[i]),
            "recall_95ci_lower": float(recall_ci[0]),
            "recall_95ci_upper": float(recall_ci[1]),
            "predicted_as_benign_missed": int(cm[i, benign_idx]) if i != benign_idx else 0
        }

    return {
        "summary": {
            "total_records": n_samples,
            "accuracy": acc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "benign_fpr": benign_fpr,
            "benign_specificity": benign_specificity,
            "attack_fnr": attack_fnr,
            "attack_detection_rate": attack_detection_rate,
            "false_positives_count": false_positives,
            "total_benign_count": total_benign,
            "missed_attacks_count": total_missed_attacks,
            "total_attacks_count": total_attacks
        },
        "missed_attacks_by_class": missed_attacks_by_class,
        "per_class_metrics": per_class_metrics,
        "confusion_matrix": cm.tolist()
    }


def compute_operating_curve(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    label_mapping: Dict[int, str],
    benign_class_name: str = "Benign",
    target_fpr_budgets: List[float] = [0.001, 0.005, 0.010, 0.020, 0.050]
) -> List[Dict[str, Any]]:
    """
    Evaluates detection operating points across false positive rate budgets (0.1% to 5.0%).
    Calibrated strictly on validation data to determine optimal threshold policies.
    """
    benign_idx = [idx for idx, name in label_mapping.items() if name == benign_class_name][0]
    attack_indices = [idx for idx in label_mapping.keys() if idx != benign_idx]
    
    # Attack probability = 1.0 - P(Benign)
    p_attack = 1.0 - y_proba[:, benign_idx]
    y_is_attack = (y_true != benign_idx).astype(int)
    
    benign_scores = p_attack[y_true == benign_idx]
    attack_scores = p_attack[y_true != benign_idx]
    total_benign = len(benign_scores)
    total_attacks = len(attack_scores)
    
    operating_points = []
    for budget in target_fpr_budgets:
        # Threshold: 100 * (1 - budget) percentile of benign scores
        thresh = float(np.percentile(benign_scores, 100.0 * (1.0 - budget)))
        actual_fpr = float((benign_scores >= thresh).sum() / total_benign)
        actual_recall = float((attack_scores >= thresh).sum() / total_attacks)
        
        # Binary precision at this operating threshold
        tp = int((attack_scores >= thresh).sum())
        fp = int((benign_scores >= thresh).sum())
        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        f1 = float(2 * prec * actual_recall / (prec + actual_recall)) if (prec + actual_recall) > 0 else 0.0
        
        operating_points.append({
            "target_fpr_budget": budget,
            "calibrated_threshold": thresh,
            "actual_benign_fpr": actual_fpr,
            "attack_recall": actual_recall,
            "binary_precision": prec,
            "binary_f1": f1,
            "false_alarms_count": fp,
            "detected_attacks_count": tp,
            "missed_attacks_count": total_attacks - tp
        })
        
    return operating_points


def test_metrics_engine():
    """Unit test suite verifying mathematical consistency of Metrics Engine."""
    print("[*] Running Metrics Engine unit test suite...")
    # Synthetic ground truth: 3 classes (0: Benign, 1: DoS, 2: SQLi)
    mapping = {0: "Benign", 1: "DoS", 2: "SQL Injection"}
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 2, 2, 0])  # 5 Benign, 3 DoS, 2 SQLi
    y_pred = np.array([0, 0, 0, 1, 1, 1, 0, 2, 0, 0])  # 1 FP (0->1), 2 FN to benign (1->0, 2->0)
    
    res = evaluate_cyber_detection_predictions(y_true, y_pred, mapping)
    s = res["summary"]
    
    assert s["total_records"] == 10
    assert s["total_benign_count"] == 5
    assert s["total_attacks_count"] == 5
    assert s["false_positives_count"] == 1  # 1 benign predicted as DoS
    assert s["benign_fpr"] == 0.20
    assert s["missed_attacks_count"] == 2  # 1 DoS predicted as Benign, 1 SQLi predicted as Benign
    assert s["attack_fnr"] == 0.40
    assert s["attack_detection_rate"] == 0.60
    assert res["missed_attacks_by_class"]["DoS"] == 1
    assert res["missed_attacks_by_class"]["SQL Injection"] == 1
    
    print("[✓] All Metrics Engine mathematical assertions passed 100%!")


if __name__ == "__main__":
    test_metrics_engine()
