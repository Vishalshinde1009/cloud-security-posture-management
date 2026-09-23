import uuid
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.cloud import Scan
from app.models.finding import Finding

logger = logging.getLogger("cspm.monitoring.change_detector")

POSTURE_CHANGE_THRESHOLD = 5.0  # Documented threshold of 5.0 points


@dataclass
class ChangeDetectionResult:
    cloud_account_id: uuid.UUID
    new_scan_id: uuid.UUID
    previous_scan_id: Optional[uuid.UUID]
    new_findings: List[Finding]
    risk_increases: List[Tuple[Finding, float, float]]  # (new_finding, prev_risk, new_risk)
    resolved_findings: List[Finding]
    posture_change: float
    is_posture_degraded: bool
    is_posture_improved: bool
    prev_security_score: Optional[float]
    new_security_score: Optional[float]

    @property
    def new_findings_count(self) -> int:
        return len(self.new_findings)

    @property
    def risk_increases_count(self) -> int:
        return len(self.risk_increases)

    @property
    def resolved_findings_count(self) -> int:
        return len(self.resolved_findings)


class ChangeDetector:
    """
    Compares two scans for the same CloudAccount to detect:
    A. New findings
    B. Risk score increases
    C. Resolved findings
    D. Posture degradation (drop >= 5.0 pts)
    E. Posture improvement (increase >= 5.0 pts)
    """

    @staticmethod
    def compare_scans(
        db: Session,
        new_scan: Scan,
        previous_scan: Optional[Scan] = None,
    ) -> ChangeDetectionResult:
        # If previous_scan not supplied, find the latest completed scan before new_scan
        if not previous_scan:
            previous_scan = db.query(Scan).filter(
                Scan.cloud_account_id == new_scan.cloud_account_id,
                Scan.status == "COMPLETED",
                Scan.id != new_scan.id,
            ).order_by(desc(Scan.completed_at)).first()

        # Load findings associated with new scan
        new_findings_all = db.query(Finding).filter(Finding.scan_id == new_scan.id).all()
        new_open_findings = [f for f in new_findings_all if f.status == "OPEN"]
        new_open_map: Dict[str, Finding] = {f.finding_identifier: f for f in new_open_findings}

        new_detected: List[Finding] = []
        risk_escalated: List[Tuple[Finding, float, float]] = []
        resolved_detected: List[Finding] = []

        prev_score: Optional[float] = None
        new_score: Optional[float] = new_scan.security_score
        posture_change: float = 0.0
        is_degraded: bool = False
        is_improved: bool = False

        if not previous_scan:
            # Baseline scan: All open findings are new findings
            new_detected = new_open_findings
            logger.info(
                f"Scan {new_scan.id} is baseline for account {new_scan.cloud_account_id}. "
                f"{len(new_detected)} initial findings detected."
            )
        else:
            prev_findings_all = db.query(Finding).filter(Finding.scan_id == previous_scan.id).all()
            prev_open_findings = [f for f in prev_findings_all if f.status == "OPEN"]
            prev_open_map: Dict[str, Finding] = {f.finding_identifier: f for f in prev_open_findings}

            # 1. New Findings: in new scan but not in previous scan
            for ident, nf in new_open_map.items():
                if ident not in prev_open_map:
                    new_detected.append(nf)
                else:
                    # 2. Risk Increased: in both, but risk_score escalated
                    pf = prev_open_map[ident]
                    if nf.risk_score > pf.risk_score:
                        risk_escalated.append((nf, pf.risk_score, nf.risk_score))

            # 3. Resolved Findings: in previous scan, but not in new open map (or marked RESOLVED)
            for ident, pf in prev_open_map.items():
                if ident not in new_open_map:
                    resolved_detected.append(pf)

            # 4 & 5. Posture change
            prev_score = previous_scan.security_score
            if prev_score is not None and new_score is not None:
                posture_change = round(new_score - prev_score, 2)
                if posture_change <= -POSTURE_CHANGE_THRESHOLD:
                    is_degraded = True
                elif posture_change >= POSTURE_CHANGE_THRESHOLD:
                    is_improved = True

        return ChangeDetectionResult(
            cloud_account_id=new_scan.cloud_account_id,
            new_scan_id=new_scan.id,
            previous_scan_id=previous_scan.id if previous_scan else None,
            new_findings=new_detected,
            risk_increases=risk_escalated,
            resolved_findings=resolved_detected,
            posture_change=posture_change,
            is_posture_degraded=is_degraded,
            is_posture_improved=is_improved,
            prev_security_score=prev_score,
            new_security_score=new_score,
        )
