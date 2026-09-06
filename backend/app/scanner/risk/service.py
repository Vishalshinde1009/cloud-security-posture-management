"""
RiskScoringService: Deterministic, explainable risk assessment and posture calculation engine.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.scanner.risk.evaluators import (
    evaluate_severity,
    evaluate_exposure,
    evaluate_asset_criticality,
    evaluate_exploitability,
    evaluate_data_sensitivity,
    evaluate_config_weakness,
)

logger = logging.getLogger("cspm.risk")

# Transparent Weight Distribution (Total = 1.0)
WEIGHT_SEVERITY = 0.40
WEIGHT_EXPOSURE = 0.20
WEIGHT_ASSET_CRITICALITY = 0.15
WEIGHT_EXPLOITABILITY = 0.10
WEIGHT_DATA_SENSITIVITY = 0.10
WEIGHT_CONFIG_WEAKNESS = 0.05

SEVERITY_PENALTY_WEIGHTS = {
    "CRITICAL": 1.00,
    "HIGH": 0.75,
    "MEDIUM": 0.40,
    "LOW": 0.15,
    "INFO": 0.00,
}


class RiskScoringService:
    @staticmethod
    def map_risk_level(score: int) -> str:
        """
        Maps a 0-100 risk score to an official risk level:
        90-100 -> CRITICAL
        70-89  -> HIGH
        40-69  -> MEDIUM
        1-39   -> LOW
        0      -> INFO
        """
        if score >= 90:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 1:
            return "LOW"
        return "INFO"

    @staticmethod
    def map_risk_priority(score: int) -> str:
        """
        Maps a 0-100 risk score to a remediation priority:
        90-100 -> IMMEDIATE
        70-89  -> HIGH
        40-69  -> MEDIUM
        0-39   -> LOW
        """
        if score >= 90:
            return "IMMEDIATE"
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def map_posture_rating(score: float) -> str:
        """
        Maps a 0-100 security posture score to an official posture rating:
        90-100 -> EXCELLENT
        75-89  -> GOOD
        60-74  -> MODERATE
        40-59  -> POOR
        0-39   -> CRITICAL
        """
        if score >= 90.0:
            return "EXCELLENT"
        if score >= 75.0:
            return "GOOD"
        if score >= 60.0:
            return "MODERATE"
        if score >= 40.0:
            return "POOR"
        return "CRITICAL"

    @classmethod
    def calculate_finding_risk(
        cls,
        severity: str,
        resource_type: str,
        resource_name: Optional[str],
        tags: Dict[str, Any],
        configuration: Dict[str, Any],
        evidence: Dict[str, Any],
        rule_id: str,
        title: str,
    ) -> Dict[str, Any]:
        """
        Calculates a deterministic 0-100 risk score and structured risk breakdown for a single finding.
        Formula:
        risk_score = round(0.40 * S + 0.20 * E + 0.15 * C + 0.10 * X + 0.10 * D + 0.05 * W)
        """
        sev_score = evaluate_severity(severity)
        exp_score, exp_reason = evaluate_exposure(resource_type, configuration, evidence, rule_id)
        crit_score, crit_reason = evaluate_asset_criticality(resource_type, resource_name, tags, configuration, rule_id)
        expl_score, expl_reason = evaluate_exploitability(resource_type, configuration, evidence, rule_id, severity)
        sens_score, sens_reason = evaluate_data_sensitivity(resource_type, resource_name, tags, configuration)
        weak_score, weak_reason = evaluate_config_weakness(rule_id, evidence, severity, configuration)

        weighted = (
            (WEIGHT_SEVERITY * sev_score)
            + (WEIGHT_EXPOSURE * exp_score)
            + (WEIGHT_ASSET_CRITICALITY * crit_score)
            + (WEIGHT_EXPLOITABILITY * expl_score)
            + (WEIGHT_DATA_SENSITIVITY * sens_score)
            + (WEIGHT_CONFIG_WEAKNESS * weak_score)
        )

        final_score = max(0, min(100, int(round(weighted))))
        risk_level = cls.map_risk_level(final_score)
        risk_priority = cls.map_risk_priority(final_score)

        explanation = (
            f"This finding received a risk score of {final_score}/100 ({risk_level} - {risk_priority} priority). "
            f"{exp_reason}. {crit_reason}. {expl_reason}."
        )

        factors = {
            "severity": sev_score,
            "exposure": exp_score,
            "asset_criticality": crit_score,
            "exploitability": expl_score,
            "data_sensitivity": sens_score,
            "config_weakness": weak_score,
            "reasons": {
                "exposure": exp_reason,
                "asset_criticality": crit_reason,
                "exploitability": expl_reason,
                "data_sensitivity": sens_reason,
                "config_weakness": weak_reason,
            },
        }

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "risk_priority": risk_priority,
            "risk_factors": factors,
            "risk_explanation": explanation,
        }

    @classmethod
    def calculate_posture_score(
        cls,
        total_resources: int,
        active_findings: List[Any],
    ) -> Dict[str, Any]:
        """
        Calculates an overall security posture score (0-100) and scan statistics.
        Formula:
        weighted_risk_sum = sum(finding.risk_score * severity_weight)
        risk_penalty = min(100.0, 0.70 * (weighted_risk_sum / (max(1, N) * 0.60)) + 0.30 * max_risk)
        security_score = max(0.0, round(100.0 - risk_penalty, 1))
        """
        if total_resources <= 0:
            return {
                "security_score": 100.0,
                "posture_rating": "EXCELLENT",
                "avg_risk": 0.0,
                "max_risk": 0,
                "immediate_count": 0,
                "high_priority_count": 0,
                "medium_priority_count": 0,
                "low_priority_count": 0,
            }

        if not active_findings:
            return {
                "security_score": 100.0,
                "posture_rating": "EXCELLENT",
                "avg_risk": 0.0,
                "max_risk": 0,
                "immediate_count": 0,
                "high_priority_count": 0,
                "medium_priority_count": 0,
                "low_priority_count": 0,
            }

        scores = [f.risk_score for f in active_findings]
        avg_risk = round(sum(scores) / len(scores), 1)
        max_risk = max(scores)

        # Count priorities
        immediate_c = sum(1 for f in active_findings if getattr(f, "risk_priority", "") == "IMMEDIATE" or f.risk_score >= 90)
        high_c = sum(1 for f in active_findings if getattr(f, "risk_priority", "") == "HIGH" or (70 <= f.risk_score < 90))
        med_c = sum(1 for f in active_findings if getattr(f, "risk_priority", "") == "MEDIUM" or (40 <= f.risk_score < 70))
        low_c = sum(1 for f in active_findings if getattr(f, "risk_priority", "") == "LOW" or f.risk_score < 40)

        weighted_risk_sum = 0.0
        for f in active_findings:
            sev_upper = f.severity.upper()
            w = SEVERITY_PENALTY_WEIGHTS.get(sev_upper, 0.50)
            weighted_risk_sum += (f.risk_score * w)

        # Asset-normalized penalty + peak finding risk influence
        normalized_asset_penalty = (weighted_risk_sum / (total_resources * 0.60))
        risk_penalty = min(100.0, (0.70 * normalized_asset_penalty) + (0.30 * max_risk))
        security_score = max(0.0, round(100.0 - risk_penalty, 1))
        posture_rating = cls.map_posture_rating(security_score)

        return {
            "security_score": security_score,
            "posture_rating": posture_rating,
            "avg_risk": avg_risk,
            "max_risk": int(max_risk),
            "immediate_count": immediate_c,
            "high_priority_count": high_c,
            "medium_priority_count": med_c,
            "low_priority_count": low_c,
        }

    @classmethod
    def compare_scans(
        cls,
        db: Session,
        current_scan: Any,
        previous_scan: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Computes historical drift and security posture progression between two sequential scans
        for the same cloud account.
        """
        from app.models.cloud import Scan
        from app.models.finding import Finding

        # If previous_scan not provided, find the immediately preceding completed scan for this account
        if not previous_scan:
            previous_scan = (
                db.query(Scan)
                .filter(
                    Scan.cloud_account_id == current_scan.cloud_account_id,
                    Scan.status == "COMPLETED",
                    Scan.created_at < current_scan.created_at,
                )
                .order_by(desc(Scan.created_at))
                .first()
            )

        if not previous_scan:
            # First scan comparison baseline
            return {
                "has_previous_scan": False,
                "current_scan_id": str(current_scan.id),
                "previous_scan_id": None,
                "score_change": 0.0,
                "risk_change": 0.0,
                "new_findings": current_scan.findings_count,
                "resolved_findings": 0,
                "persistent_findings": 0,
                "previous_security_score": None,
                "current_security_score": current_scan.security_score,
                "previous_posture_rating": None,
                "current_posture_rating": current_scan.posture_rating or "GOOD",
            }

        prev_score = previous_scan.security_score or 0.0
        curr_score = current_scan.security_score or 0.0
        score_change = round(curr_score - prev_score, 1)

        prev_risk = previous_scan.risk_summary.get("avg_risk", 0.0) if previous_scan.risk_summary else 0.0
        curr_risk = current_scan.risk_summary.get("avg_risk", 0.0) if current_scan.risk_summary else 0.0
        risk_change = round(curr_risk - prev_risk, 1)

        # Findings comparisons
        # New findings: first_detected >= previous_scan.created_at
        new_count = (
            db.query(Finding)
            .filter(
                Finding.cloud_account_id == current_scan.cloud_account_id,
                Finding.first_detected >= previous_scan.created_at,
            )
            .count()
        )

        # Resolved findings: resolved_at >= previous_scan.created_at
        resolved_count = (
            db.query(Finding)
            .filter(
                Finding.cloud_account_id == current_scan.cloud_account_id,
                Finding.status == "RESOLVED",
                Finding.resolved_at >= previous_scan.created_at,
            )
            .count()
        )

        # Persistent findings: active in both
        persistent_count = max(0, current_scan.findings_count - new_count)

        return {
            "has_previous_scan": True,
            "current_scan_id": str(current_scan.id),
            "previous_scan_id": str(previous_scan.id),
            "score_change": score_change,
            "risk_change": risk_change,
            "new_findings": new_count,
            "resolved_findings": resolved_count,
            "persistent_findings": persistent_count,
            "previous_security_score": prev_score,
            "current_security_score": curr_score,
            "previous_posture_rating": previous_scan.posture_rating,
            "current_posture_rating": current_scan.posture_rating,
        }
