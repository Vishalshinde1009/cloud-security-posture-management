import uuid
import logging
from typing import List, Tuple, Optional, Dict, Any, Set
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_

from app.models.finding import SecurityRule, Finding
from app.models.cloud import CloudAccount, Scan, Resource
from app.models.base import utc_now
from app.scanner.rules.registry import default_registry
from app.scanner.rules.executor import FindingCandidate
from app.scanner.risk.service import RiskScoringService

logger = logging.getLogger("cspm.services.findings")

SEVERITY_BASE_SCORES = {
    "CRITICAL": 100.0,
    "HIGH": 75.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
}


class FindingService:
    @staticmethod
    def sync_security_rules_to_db(db: Session) -> int:
        """
        Synchronizes all 26 registered detection rules into the PostgreSQL/SQLite security_rules table.
        Ensures foreign keys and rule catalogs are consistently populated.
        """
        registered = default_registry.get_all_rules()
        synced_count = 0

        for r in registered:
            db_rule = db.query(SecurityRule).filter(SecurityRule.rule_id == r.rule_id).first()
            if not db_rule:
                db_rule = SecurityRule(
                    id=uuid.uuid4(),
                    rule_id=r.rule_id,
                    title=r.title,
                    description=r.description,
                    service=r.service,
                    resource_type=r.resource_type,
                    severity=r.severity,
                    category=r.category,
                    remediation=r.remediation,
                    references=r.references,
                    enabled=True,
                )
                db.add(db_rule)
                synced_count += 1
            else:
                # Update metadata if needed
                db_rule.title = r.title
                db_rule.description = r.description
                db_rule.service = r.service
                db_rule.resource_type = r.resource_type
                db_rule.severity = r.severity
                db_rule.category = r.category
                db_rule.remediation = r.remediation
                db_rule.references = r.references

        db.commit()
        logger.info(f"Synchronized {len(registered)} security rules to database ({synced_count} newly inserted).")
        return len(registered)

    @staticmethod
    def persist_finding_candidates(
        db: Session,
        scan: Scan,
        account: CloudAccount,
        candidates: List[FindingCandidate],
        scanned_resource_ids: Set[str],
    ) -> Tuple[List[Finding], int, int, int, int]:
        """
        Persists detected violations with deterministic deduplication:
        - Re-identified findings update last_detected without duplicating rows.
        - Previously open findings on scanned resources that are no longer detected transition to RESOLVED.
        - Computes severity counts for the scan summary.
        """
        now = utc_now()

        # Build rule & resource caches
        rules_map = {r.rule_id: r for r in db.query(SecurityRule).all()}
        resources_map = {
            res.resource_id: res for res in db.query(Resource).filter(Resource.cloud_account_id == account.id).all()
        }

        active_fingerprints: Set[str] = set()
        active_findings: List[Finding] = []

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for candidate in candidates:
            rule_id = candidate.rule.rule_id
            res_id = candidate.resource.resource_id
            fingerprint = candidate.finding_identifier

            active_fingerprints.add(fingerprint)

            db_rule = rules_map.get(rule_id)
            db_resource = resources_map.get(res_id)

            if not db_rule or not db_resource:
                logger.warning(f"Skipping candidate for missing rule ({rule_id}) or resource ({res_id})")
                continue

            severity = candidate.result.severity or candidate.rule.severity

            # Deterministic, explainable risk scoring via RiskScoringService
            risk_calc = RiskScoringService.calculate_finding_risk(
                severity=severity,
                resource_type=db_resource.resource_type,
                resource_name=db_resource.resource_name,
                tags=db_resource.tags or {},
                configuration=db_resource.configuration or {},
                evidence=candidate.result.evidence or {},
                rule_id=db_rule.rule_id,
                title=candidate.rule.title,
            )

            # Check if an existing finding exists for this account & fingerprint
            existing = db.query(Finding).filter(
                Finding.cloud_account_id == account.id,
                Finding.finding_identifier == fingerprint,
            ).first()

            if existing:
                existing.scan_id = scan.id
                existing.status = "OPEN"
                existing.last_detected = now
                existing.resolved_at = None
                existing.evidence = candidate.result.evidence
                existing.severity = severity
                existing.risk_score = risk_calc["risk_score"]
                existing.risk_level = risk_calc["risk_level"]
                existing.risk_priority = risk_calc["risk_priority"]
                existing.risk_factors = risk_calc["risk_factors"]
                existing.risk_explanation = risk_calc["risk_explanation"]
                existing.risk_calculated_at = now
                existing.remediation = candidate.result.remediation or candidate.rule.remediation
                active_findings.append(existing)
            else:
                new_finding = Finding(
                    id=uuid.uuid4(),
                    rule_id=db_rule.id,
                    scan_id=scan.id,
                    cloud_account_id=account.id,
                    resource_id=db_resource.id,
                    finding_identifier=fingerprint,
                    title=candidate.rule.title,
                    description=candidate.result.reason or candidate.rule.description,
                    severity=severity,
                    risk_score=risk_calc["risk_score"],
                    risk_level=risk_calc["risk_level"],
                    risk_priority=risk_calc["risk_priority"],
                    risk_factors=risk_calc["risk_factors"],
                    risk_explanation=risk_calc["risk_explanation"],
                    risk_calculated_at=now,
                    status="OPEN",
                    remediation=candidate.result.remediation or candidate.rule.remediation,
                    evidence=candidate.result.evidence,
                    first_detected=now,
                    last_detected=now,
                )
                db.add(new_finding)
                active_findings.append(new_finding)

            # Count severities
            sev_upper = severity.upper()
            if sev_upper == "CRITICAL":
                critical_count += 1
            elif sev_upper == "HIGH":
                high_count += 1
            elif sev_upper == "MEDIUM":
                medium_count += 1
            elif sev_upper == "LOW":
                low_count += 1

        # Drift Resolution: Previously open findings on resources that were scanned,
        # but are no longer triggered, transition to RESOLVED
        all_open_findings = db.query(Finding).filter(
            Finding.cloud_account_id == account.id,
            Finding.status == "OPEN",
        ).all()

        for old_f in all_open_findings:
            if old_f.finding_identifier not in active_fingerprints:
                # Check if the associated resource was part of this scan
                if old_f.resource and old_f.resource.resource_id in scanned_resource_ids:
                    old_f.status = "RESOLVED"
                    old_f.resolved_at = now
                    logger.info(f"Finding {old_f.id} ({old_f.title}) resolved due to clean scan.")

        db.commit()
        return active_findings, critical_count, high_count, medium_count, low_count

    @staticmethod
    def update_resource_security_statuses(db: Session, account_id: uuid.UUID) -> None:
        """
        Recalculates and updates security_status for all resources belonging to the account:
        - CRITICAL: Any open CRITICAL severity finding exists on resource.
        - AT_RISK: Any open HIGH or MEDIUM severity finding exists on resource.
        - SECURE: No open findings exist.
        """
        resources = db.query(Resource).filter(Resource.cloud_account_id == account_id).all()

        for res in resources:
            open_findings = db.query(Finding).filter(
                Finding.resource_id == res.id,
                Finding.status == "OPEN",
            ).all()

            if not open_findings:
                res.security_status = "SECURE"
            else:
                has_critical = any(f.severity.upper() == "CRITICAL" for f in open_findings)
                if has_critical:
                    res.security_status = "CRITICAL"
                else:
                    res.security_status = "AT_RISK"

        db.commit()

    @staticmethod
    def get_findings(
        db: Session,
        account_id: Optional[uuid.UUID] = None,
        severity: Optional[str] = None,
        service: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        resource_id: Optional[uuid.UUID] = None,
        risk_level: Optional[str] = None,
        risk_priority: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        max_risk_score: Optional[float] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Retrieves paginated findings with multi-criteria filtering and enriched resource/rule metadata.
        """
        query = db.query(Finding).join(SecurityRule).join(Resource)

        if account_id:
            query = query.filter(Finding.cloud_account_id == account_id)
        if severity:
            query = query.filter(Finding.severity == severity.upper())
        if status:
            query = query.filter(Finding.status == status.upper())
        if service:
            query = query.filter(Resource.service == service.upper())
        if rule_id:
            query = query.filter(SecurityRule.rule_id == rule_id.upper())
        if resource_id:
            query = query.filter(Finding.resource_id == resource_id)
        if risk_level:
            query = query.filter(Finding.risk_level == risk_level.upper())
        if risk_priority:
            query = query.filter(Finding.risk_priority == risk_priority.upper())
        if min_risk_score is not None:
            query = query.filter(Finding.risk_score >= min_risk_score)
        if max_risk_score is not None:
            query = query.filter(Finding.risk_score <= max_risk_score)
        if search:
            search_pattern = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    Finding.title.ilike(search_pattern),
                    Finding.description.ilike(search_pattern),
                    SecurityRule.rule_id.ilike(search_pattern),
                    Resource.resource_name.ilike(search_pattern),
                    Resource.resource_id.ilike(search_pattern),
                )
            )

        total = query.count()
        findings = query.order_by(desc(Finding.risk_score), desc(Finding.created_at)).offset(offset).limit(limit).all()

        enriched = []
        for f in findings:
            enriched.append({
                "id": f.id,
                "rule_id": f.rule_id,
                "scan_id": f.scan_id,
                "cloud_account_id": f.cloud_account_id,
                "resource_id": f.resource_id,
                "finding_identifier": f.finding_identifier,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "risk_level": f.risk_level,
                "risk_priority": f.risk_priority,
                "risk_factors": f.risk_factors or {},
                "risk_explanation": f.risk_explanation,
                "risk_calculated_at": f.risk_calculated_at,
                "status": f.status,
                "remediation": f.remediation,
                "first_detected": f.first_detected,
                "last_detected": f.last_detected,
                "resolved_at": f.resolved_at,
                "created_at": f.created_at,
                "rule_code": f.rule.rule_id if f.rule else None,
                "service": f.resource.service if f.resource else None,
                "resource_name": f.resource.resource_name if f.resource else None,
                "resource_identifier": f.resource.resource_id if f.resource else None,
            })

        return enriched, total

    @staticmethod
    def get_finding_by_id(db: Session, finding_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Retrieves a single finding with full technical configuration evidence."""
        f = db.query(Finding).filter(Finding.id == finding_id).first()
        if not f:
            return None

        return {
            "id": f.id,
            "rule_id": f.rule_id,
            "scan_id": f.scan_id,
            "cloud_account_id": f.cloud_account_id,
            "resource_id": f.resource_id,
            "finding_identifier": f.finding_identifier,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "risk_level": f.risk_level,
            "risk_priority": f.risk_priority,
            "risk_factors": f.risk_factors or {},
            "risk_explanation": f.risk_explanation,
            "risk_calculated_at": f.risk_calculated_at,
            "status": f.status,
            "remediation": f.remediation,
            "evidence": f.evidence,
            "first_detected": f.first_detected,
            "last_detected": f.last_detected,
            "resolved_at": f.resolved_at,
            "created_at": f.created_at,
            "rule_code": f.rule.rule_id if f.rule else None,
            "service": f.resource.service if f.resource else None,
            "resource_name": f.resource.resource_name if f.resource else None,
            "resource_identifier": f.resource.resource_id if f.resource else None,
            "references": f.rule.references if f.rule else [],
        }

    @staticmethod
    def get_rules(
        db: Session,
        service: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        enabled: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[SecurityRule], int]:
        """Retrieves paginated security rules catalog with multi-field filtering."""
        query = db.query(SecurityRule)

        if service:
            query = query.filter(SecurityRule.service == service.upper())
        if category:
            query = query.filter(SecurityRule.category.ilike(f"%{category}%"))
        if severity:
            query = query.filter(SecurityRule.severity == severity.upper())
        if enabled is not None:
            query = query.filter(SecurityRule.enabled == enabled)

        total = query.count()
        rules = query.order_by(SecurityRule.rule_id).offset(offset).limit(limit).all()
        return rules, total

    @staticmethod
    def get_rule_by_id(db: Session, identifier: str) -> Optional[SecurityRule]:
        """Retrieves rule by UUID or canonical rule_id (e.g., 'S3-001')."""
        try:
            val_uuid = uuid.UUID(identifier)
            return db.query(SecurityRule).filter(SecurityRule.id == val_uuid).first()
        except ValueError:
            return db.query(SecurityRule).filter(SecurityRule.rule_id == identifier.upper()).first()
