"""
Compliance Service for Security Framework Alignment & Gap Analysis.
Provides deterministic mapping and status computation for CIS AWS, NIST, ISO 27001, and PCI DSS.
Note: Results represent informational security-control alignment, not formal certification.
"""

import uuid
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.models.compliance import ComplianceControl, FindingCompliance
from app.models.finding import Finding, SecurityRule
from app.compliance.catalog import COMPLIANCE_FRAMEWORKS, COMPLIANCE_CONTROLS, RULE_COMPLIANCE_MAPPINGS

logger = logging.getLogger("cspm.services.compliance")


class ComplianceService:
    @staticmethod
    def sync_compliance_catalog(db: Session) -> int:
        """
        Synchronizes all pre-defined compliance framework controls into the compliance_controls table.
        Idempotent: safely creates missing controls and preserves existing mappings.
        """
        synced_count = 0
        for ctrl_data in COMPLIANCE_CONTROLS:
            existing = db.query(ComplianceControl).filter(
                ComplianceControl.framework == ctrl_data["framework"],
                ComplianceControl.control_id == ctrl_data["control_id"],
            ).first()

            if not existing:
                ctrl = ComplianceControl(
                    id=uuid.uuid4(),
                    framework=ctrl_data["framework"],
                    control_id=ctrl_data["control_id"],
                    title=ctrl_data["title"],
                    description=ctrl_data["description"],
                )
                db.add(ctrl)
                synced_count += 1
            else:
                existing.title = ctrl_data["title"]
                existing.description = ctrl_data["description"]

        db.commit()
        if synced_count > 0:
            logger.info(f"Synchronized {synced_count} new compliance controls to database.")
        return len(COMPLIANCE_CONTROLS)

    @staticmethod
    def map_findings_to_compliance(db: Session, findings: List[Finding]) -> int:
        """
        Links active security findings to corresponding compliance framework controls.
        Creates or updates FindingCompliance records deterministically.
        """
        ComplianceService.sync_compliance_catalog(db)

        # Cache controls map: (framework, control_id) -> ComplianceControl
        all_controls = db.query(ComplianceControl).all()
        controls_map = {(c.framework, c.control_id): c for c in all_controls}

        mappings_created = 0
        for finding in findings:
            # Resolve rule_id
            rule_id = None
            if finding.rule:
                rule_id = finding.rule.rule_id
            else:
                db_rule = db.query(SecurityRule).filter(SecurityRule.id == finding.rule_id).first()
                if db_rule:
                    rule_id = db_rule.rule_id

            if not rule_id or rule_id not in RULE_COMPLIANCE_MAPPINGS:
                continue

            framework_map = RULE_COMPLIANCE_MAPPINGS[rule_id]
            is_failing = finding.status in ("OPEN", "IN_PROGRESS")
            target_status = "FAIL" if is_failing else "PASS"

            for framework, ctrl_id in framework_map.items():
                control = controls_map.get((framework, ctrl_id))
                if not control:
                    continue

                existing_map = db.query(FindingCompliance).filter(
                    FindingCompliance.finding_id == finding.id,
                    FindingCompliance.compliance_control_id == control.id,
                ).first()

                if existing_map:
                    existing_map.status = target_status
                    existing_map.notes = f"Finding status: {finding.status} (Severity: {finding.severity})"
                else:
                    new_map = FindingCompliance(
                        id=uuid.uuid4(),
                        finding_id=finding.id,
                        compliance_control_id=control.id,
                        status=target_status,
                        notes=f"Mapped via detection rule {rule_id}. Finding status: {finding.status}",
                    )
                    db.add(new_map)
                    mappings_created += 1

        db.commit()
        logger.info(f"Processed compliance mappings for {len(findings)} findings ({mappings_created} new links).")
        return mappings_created

    @staticmethod
    def get_framework_summary(
        db: Session,
        framework: str,
        account_id: Optional[uuid.UUID] = None,
        user: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Calculates deterministic compliance coverage metrics and potential gaps for a specific framework with user isolation.
        """
        from app.models.cloud import CloudAccount
        from app.core.config import settings
        from app.api.deps import is_admin

        if not account_id:
            if user and not is_admin(user):
                user_acc = db.query(CloudAccount).filter(CloudAccount.user_id == user.id, CloudAccount.is_active == True).first()
                if user_acc:
                    account_id = user_acc.id
            else:
                if settings.CSPM_MODE.lower() == "aws":
                    aws_acc = db.query(CloudAccount).filter(CloudAccount.provider == "AWS", CloudAccount.is_active == True).first()
                    if aws_acc:
                        account_id = aws_acc.id
                elif settings.CSPM_MODE.lower() == "mock":
                    demo_acc = db.query(CloudAccount).filter(CloudAccount.provider == "MOCK").first()
                    if demo_acc:
                        account_id = demo_acc.id


        ComplianceService.sync_compliance_catalog(db)

        framework_key = framework.upper().replace("-", "_")
        if framework_key not in COMPLIANCE_FRAMEWORKS:
            # Try matching directly
            matched = next((k for k in COMPLIANCE_FRAMEWORKS if k.upper() == framework_key), None)
            if not matched:
                raise ValueError(f"Unknown compliance framework '{framework}'. Supported: {list(COMPLIANCE_FRAMEWORKS.keys())}")
            framework_key = matched

        meta = COMPLIANCE_FRAMEWORKS[framework_key]
        controls = db.query(ComplianceControl).filter(ComplianceControl.framework == framework_key).all()
        total_controls = len(controls)

        from app.api.deps import is_admin, get_user_accessible_account_ids
        accessible_ids = None
        if user and not is_admin(user):
            accessible_ids = get_user_accessible_account_ids(db, user)

        if not account_id:
            from app.models.cloud import CloudAccount
            from app.core.config import settings
            if user and not is_admin(user):
                user_acc = db.query(CloudAccount).filter(CloudAccount.user_id == user.id, CloudAccount.is_active == True).first()
                if user_acc:
                    account_id = user_acc.id
            else:
                if settings.CSPM_MODE.lower() == "aws":
                    aws_acc = db.query(CloudAccount).filter(CloudAccount.provider == "AWS", CloudAccount.is_active == True).first()
                    if aws_acc:
                        account_id = aws_acc.id
                elif settings.CSPM_MODE.lower() == "mock":
                    demo_acc = db.query(CloudAccount).filter(CloudAccount.provider == "MOCK").first()
                    if demo_acc:
                        account_id = demo_acc.id

        passing_controls = 0
        failing_controls = 0
        not_assessed_controls = 0
        controls_with_findings = 0

        for ctrl in controls:
            # Query finding mappings for this control
            query = db.query(FindingCompliance).filter(FindingCompliance.compliance_control_id == ctrl.id)
            if accessible_ids is not None:
                query = query.join(Finding).filter(Finding.cloud_account_id.in_(accessible_ids))
            if account_id:
                if accessible_ids is None:
                    query = query.join(Finding)
                query = query.filter(Finding.cloud_account_id == account_id)

            mappings = query.all()

            if not mappings:
                not_assessed_controls += 1
            else:
                has_active_fail = any(m.status == "FAIL" for m in mappings)
                if has_active_fail:
                    failing_controls += 1
                    controls_with_findings += 1
                else:
                    passing_controls += 1

        # Calculate deterministic coverage percentage
        assessed_controls = passing_controls + failing_controls
        if assessed_controls > 0:
            coverage_pct = round((passing_controls / assessed_controls) * 100, 1)
        else:
            coverage_pct = 0.0

        return {
            "framework": framework_key,
            "framework_name": meta["name"],
            "version": meta["version"],
            "description": meta["description"],
            "total_controls": total_controls,
            "assessed_controls": assessed_controls,
            "passing_controls": passing_controls,
            "failing_controls": failing_controls,
            "not_assessed_controls": not_assessed_controls,
            "controls_with_findings": controls_with_findings,
            "coverage_percentage": coverage_pct,
            "compliance_disclaimer": (
                "Informational security control alignment. Results reflect configuration audit against "
                f"{meta['name']} guidelines and do not constitute formal regulatory certification."
            ),
        }

    @staticmethod
    def get_all_frameworks_overview(
        db: Session,
        account_id: Optional[uuid.UUID] = None,
        user: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Returns high-level coverage overview across all 4 supported frameworks with user isolation."""
        ComplianceService.sync_compliance_catalog(db)
        results = []
        for fw_key in COMPLIANCE_FRAMEWORKS:
            summary = ComplianceService.get_framework_summary(db, fw_key, account_id=account_id, user=user)
            results.append(summary)
        return results

    @staticmethod
    def get_framework_controls(
        db: Session,
        framework: str,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        service_filter: Optional[str] = None,
        account_id: Optional[uuid.UUID] = None,
        user: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns the catalog of controls for a framework with mapped findings,
        resources, and pass/fail/not_assessed status with user isolation.
        """
        ComplianceService.sync_compliance_catalog(db)
        framework_key = framework.upper().replace("-", "_")

        from app.models.cloud import CloudAccount
        from app.core.config import settings
        from app.api.deps import is_admin, get_user_accessible_account_ids

        accessible_ids = None
        if user and not is_admin(user):
            accessible_ids = get_user_accessible_account_ids(db, user)

        if not account_id:
            if user and not is_admin(user):
                user_acc = db.query(CloudAccount).filter(CloudAccount.user_id == user.id, CloudAccount.is_active == True).first()
                if user_acc:
                    account_id = user_acc.id
            else:
                if settings.CSPM_MODE.lower() == "aws":
                    aws_acc = db.query(CloudAccount).filter(CloudAccount.provider == "AWS", CloudAccount.is_active == True).first()
                    if aws_acc:
                        account_id = aws_acc.id
                elif settings.CSPM_MODE.lower() == "mock":
                    demo_acc = db.query(CloudAccount).filter(CloudAccount.provider == "MOCK").first()
                    if demo_acc:
                        account_id = demo_acc.id

        controls = db.query(ComplianceControl).filter(ComplianceControl.framework == framework_key).all()
        results = []

        for ctrl in controls:
            query = db.query(FindingCompliance).filter(FindingCompliance.compliance_control_id == ctrl.id)
            if accessible_ids is not None:
                query = query.join(Finding).filter(Finding.cloud_account_id.in_(accessible_ids))
            if account_id:
                if accessible_ids is None:
                    query = query.join(Finding)
                query = query.filter(Finding.cloud_account_id == account_id)

            mappings = query.all()

            findings_list = []
            has_fail = False
            max_severity = "LOW"
            services_set = set()

            sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

            for m in mappings:
                f = m.finding
                if f:
                    if m.status == "FAIL":
                        has_fail = True
                        if sev_order.get(f.severity.upper(), 0) > sev_order.get(max_severity.upper(), 0):
                            max_severity = f.severity.upper()

                    if f.resource:
                        services_set.add(f.resource.service)

                    findings_list.append({
                        "finding_id": str(f.id),
                        "title": f.title,
                        "severity": f.severity,
                        "status": f.status,
                        "risk_score": f.risk_score,
                        "resource_id": f.resource.resource_id if f.resource else "N/A",
                        "service": f.resource.service if f.resource else "N/A",
                    })

            if not mappings:
                ctrl_status = "NOT_ASSESSED"
            elif has_fail:
                ctrl_status = "FAILING"
            else:
                ctrl_status = "PASSING"

            # Apply filters
            if status_filter and status_filter.upper() != "ALL":
                if ctrl_status != status_filter.upper():
                    continue

            if severity_filter and severity_filter.upper() != "ALL":
                if has_fail and max_severity != severity_filter.upper():
                    continue
                elif not has_fail:
                    continue

            if service_filter and service_filter.upper() != "ALL":
                if service_filter.upper() not in [s.upper() for s in services_set]:
                    continue

            results.append({
                "id": str(ctrl.id),
                "framework": ctrl.framework,
                "control_id": ctrl.control_id,
                "control_title": ctrl.title,
                "title": ctrl.title,
                "description": ctrl.description,
                "status": "COMPLIANT" if ctrl_status != "FAILING" else "NON_COMPLIANT",
                "ctrl_status": ctrl_status,
                "rule_id": ctrl.control_id,
                "rule_title": ctrl.title,
                "severity": max_severity if has_fail else "LOW",
                "service": sorted(list(services_set))[0] if services_set else "AWS",
                "remediation": f"Ensure configuration complies with {ctrl.framework} control {ctrl.control_id}.",
                "open_findings_count": len(findings_list),
                "findings_count": len(findings_list),
                "max_severity": max_severity if has_fail else None,
                "services": sorted(list(services_set)),
                "findings": findings_list,
                "mapped_findings": findings_list,
            })

        return results

    @staticmethod
    def list_frameworks() -> List[Dict[str, Any]]:
        """Returns metadata for all supported compliance benchmarks."""
        return [
            {
                "id": key,
                "name": meta["name"],
                "version": meta["version"],
                "description": meta["description"],
                "icon": meta.get("icon", "ShieldCheck"),
            }
            for key, meta in COMPLIANCE_FRAMEWORKS.items()
        ]
