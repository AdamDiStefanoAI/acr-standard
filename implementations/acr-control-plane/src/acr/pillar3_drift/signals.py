"""Pillar 3: Drift signal definitions — individual behavioral metrics."""

from __future__ import annotations

from typing import NamedTuple

from acr.pillar3_drift.models import DriftSignal

# Minimum samples before a baseline is considered usable for scoring.
# Kept deliberately low: at 30, a new agent's first 30 actions ran with no
# drift signal at all, which is precisely the window where a misconfigured
# or compromised agent does its early damage. Scores from a thin baseline
# are noisier; the graduated response tiers absorb that noise.
MIN_BASELINE_SAMPLES = 10

# Weights for each signal in composite score computation
SIGNAL_WEIGHTS: dict[str, float] = {
    "tool_call_frequency": 0.25,  # calls per minute vs baseline
    "denial_rate": 0.35,  # policy denial % (high weight — key anomaly indicator)
    "error_rate": 0.20,  # tool execution error %
    "action_diversity": 0.20,  # entropy of action type distribution
}


class RawMetrics(NamedTuple):
    """Raw behavioral metrics collected over a recent window."""

    tool_calls_per_minute: float
    denial_rate: float  # 0.0–1.0
    error_rate: float  # 0.0–1.0
    action_diversity: float  # Shannon entropy of tool distribution, normalized 0.0–1.0


def compute_z_score(current: float, mean: float, std: float) -> float:
    """Compute z-score, clamping to avoid NaN/inf."""
    if std < 1e-9:
        return 0.0
    return (current - mean) / std


def z_to_drift_contribution(z: float) -> float:
    """
    Convert a z-score to a drift contribution in [0, 1].
    Uses a sigmoid-like mapping: z=0 → 0.0, z=3 → ~0.95.
    """
    # Normalize: each unit of z contributes proportionally
    # cap at abs(z) = 5 to avoid extreme outliers dominating
    capped = min(abs(z), 5.0)
    return capped / 5.0


def compute_signals(metrics: RawMetrics, baseline: dict) -> list[DriftSignal]:
    """
    Compare current raw metrics to baseline stats.
    Returns a list of DriftSignal objects.
    """
    signals: list[DriftSignal] = []

    metric_map = {
        "tool_call_frequency": metrics.tool_calls_per_minute,
        "denial_rate": metrics.denial_rate,
        "error_rate": metrics.error_rate,
        "action_diversity": metrics.action_diversity,
    }

    for name, current_val in metric_map.items():
        stats = baseline.get(name, {})
        mean = float(stats.get("mean", 0.0))
        std = float(stats.get("std", 1.0))
        weight = SIGNAL_WEIGHTS.get(name, 1.0)
        z = compute_z_score(current_val, mean, std)
        contribution = z_to_drift_contribution(z) * weight
        signals.append(
            DriftSignal(
                name=name,
                current_value=current_val,
                baseline_mean=mean,
                baseline_std=std,
                z_score=z,
                weight=weight,
                normalized_contribution=contribution,
            )
        )

    return signals


def composite_drift_score(signals: list[DriftSignal]) -> float:
    """
    Compute weighted composite drift score in [0, 1].
    """
    total_weight = sum(s.weight for s in signals)
    if total_weight < 1e-9:
        return 0.0
    raw = sum(s.normalized_contribution for s in signals) / total_weight
    return min(1.0, max(0.0, raw))
