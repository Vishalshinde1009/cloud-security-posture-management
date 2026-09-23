import logging
import uuid
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_

from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import SecurityRule
from app.models.auth import User
from app.models.audit import AuditLog
from app.models.base import utc_now
from app.core.config import settings
from app.core.json_utils import to_json_safe
from app.scanner.providers.mock.provider import MockProvider
from app.scanner.providers.aws.provider import AWSProvider
from app.scanner.engine.scanner import ScannerEngine
from app.scanner.rules.executor import RuleExecutor
from app.services.finding_service import FindingService
from app.scanner.risk.service import RiskScoringService

logger = logging.getLogger("cspm.scanner")


class ScanService:
    @staticmethod
    def get_or_create_demo_account(db: Session) -> CloudAccount:
        """
        Retrieves or initializes the safe demonstration mock cloud account.
        Ensures a known simulated environment exists for demonstration and tests.
        """
        account = db.query(CloudAccount).filter(
            CloudAccount.provider == "MOCK",
            CloudAccount.account_identifier == "mock-account-001"
        ).first()

        if not account:
            account = CloudAccount(
                name="Demo AWS Environment (Simulated)",
                provider="MOCK",
                account_identifier="mock-account-001",
                default_region="us-east-1",
                credential_mode="MOCK",
                is_active=True,
            )
            db.add(account)
            db.commit()
            db.refresh(account)
            logger.info(f"Initialized demo mock cloud account ID: {account.id}")

        return account

    @staticmethod
    def trigger_scan(
        db: Session,
        user: User,
        account_id: Optional[uuid.UUID] = None,
        client_ip: Optional[str] = None,
    ) -> Scan:
        """
        Executes a CSPM discovery scan against the target cloud account.
        Transitions state: QUEUED -> RUNNING -> COMPLETED (or FAILED).
        Persists discovered resources, tags, and configuration evidence.
        Preserves scan history without overwriting previous runs.
        """
        # Resolve target cloud account
        from app.api.deps import is_admin
        if account_id:
            account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
            if not account:
                raise ValueError(f"Cloud account with ID {account_id} not found.")
            if not is_admin(user) and account.user_id != user.id:
                raise ValueError(f"Cloud account with ID {account_id} not found.")
        else:
            account = None
            if not is_admin(user):
                account = db.query(CloudAccount).filter(
                    CloudAccount.user_id == user.id,
                    CloudAccount.is_active == True,
                ).order_by(desc(CloudAccount.created_at)).first()
                if not account:
                    account = db.query(CloudAccount).filter(
                        CloudAccount.user_id.is_(None),
                        CloudAccount.is_active == True,
                    ).order_by(desc(CloudAccount.created_at)).first()
            else:
                if settings.CSPM_MODE.lower() == "aws":
                    account = db.query(CloudAccount).filter(
                        CloudAccount.provider == "AWS",
                        CloudAccount.is_active == True,
                    ).order_by(desc(CloudAccount.created_at)).first()

                if not account:
                    account = ScanService.get_or_create_demo_account(db)

            if not account:
                account = ScanService.get_or_create_demo_account(db)

        # Initialize Scan record in QUEUED state
        scan = Scan(
            cloud_account_id=account.id,
            status="QUEUED",
            started_at=utc_now(),
            resources_scanned=0,
            findings_count=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        logger.info(f"Scan {scan.id} queued for account '{account.name}' ({account.account_identifier}) by user '{user.username}'.")

        try:
            # Transition to RUNNING
            scan.status = "RUNNING"
            db.commit()

            # Instantiate Provider & Engine based on account provider and system mode
            if account.provider.upper() == "AWS" or (settings.CSPM_MODE.lower() == "aws" and account.provider.upper() != "MOCK"):
                if account.credential_mode == "ROLE" and not account.role_arn:
                    raise ValueError(
                        f"Cloud account '{account.name}' is configured for ROLE credential mode, "
                        "but no IAM Role ARN is configured. Please configure Role ARN before scanning."
                    )
                logger.info(f"Initializing AWSProvider for account '{account.account_identifier}' in region '{account.default_region}' (Strict AWS Mode)")
                provider = AWSProvider(
                    account_id=account.account_identifier,
                    default_region=account.default_region or settings.AWS_DEFAULT_REGION,
                    role_arn=account.role_arn,
                    external_id=account.external_id,
                )
            else:
                logger.info(f"Initializing MockProvider for simulated account '{account.account_identifier}'")
                provider = MockProvider(
                    account_id=account.account_identifier,
                    default_region=account.default_region,
                )
            engine = ScannerEngine(provider=provider)

            # Run Discovery Pipeline
            discovered_items = engine.run_discovery_pipeline()

            # Upsert Resource records (JSON-safe normalized)
            now = utc_now()
            scanned_resource_ids = set()
            try:
                for item in discovered_items:
                    scanned_resource_ids.add(item.resource_id)
                    existing_res = db.query(Resource).filter(
                        Resource.cloud_account_id == account.id,
                        Resource.resource_id == item.resource_id,
                    ).first()

                    safe_tags = to_json_safe(item.tags or {})
                    safe_config = to_json_safe(item.configuration or {})

                    if existing_res:
                        existing_res.scan_id = scan.id
                        existing_res.resource_name = item.resource_name
                        existing_res.region = item.region
                        existing_res.tags = safe_tags
                        existing_res.configuration = safe_config
                        existing_res.last_seen = now
                    else:
                        new_res = Resource(
                            cloud_account_id=account.id,
                            scan_id=scan.id,
                            provider=item.provider,
                            service=item.service,
                            resource_type=item.resource_type,
                            resource_id=item.resource_id,
                            resource_name=item.resource_name,
                            region=item.region,
                            tags=safe_tags,
                            configuration=safe_config,
                            security_status="UNKNOWN",
                            first_seen=now,
                            last_seen=now,
                        )
                        db.add(new_res)

                db.commit()
            except Exception as res_err:
                db.rollback()
                logger.error(f"Failed to persist discovered resources for scan {scan.id}: {res_err}", exc_info=True)
                raise

            # Ensure rules are synchronized in DB
            FindingService.sync_security_rules_to_db(db)

            # Query any disabled rule IDs from database
            disabled_db_rules = db.query(SecurityRule.rule_id).filter(SecurityRule.enabled == False).all()
            disabled_rule_ids = {r[0] for r in disabled_db_rules}

            # Execute Security Rules
            executor = RuleExecutor()
            candidates, exec_errors = executor.execute_rules(discovered_items, disabled_rule_ids=disabled_rule_ids)

            # Persist Findings with deterministic deduplication & drift tracking
            active_findings, crit_c, high_c, med_c, low_c = FindingService.persist_finding_candidates(
                db=db,
                scan=scan,
                account=account,
                candidates=candidates,
                scanned_resource_ids=scanned_resource_ids,
            )

            # Recalculate resource security status (CRITICAL, AT_RISK, SECURE)
            FindingService.update_resource_security_statuses(db, account.id)

            # Map active findings to compliance framework controls
            from app.services.compliance_service import ComplianceService
            ComplianceService.map_findings_to_compliance(db, active_findings)

            # Tally metrics
            total_scanned = len(discovered_items)
            completed_time = utc_now()
            started = scan.started_at
            if started and started.tzinfo is None:
                started = started.replace(tzinfo=completed_time.tzinfo)
            duration_secs = (completed_time - started).total_seconds() if started else 0.0

            # Calculate explainable security posture score and risk statistics
            posture_data = RiskScoringService.calculate_posture_score(
                total_resources=total_scanned,
                active_findings=active_findings,
            )
            security_score = posture_data["security_score"]
            posture_rating = posture_data["posture_rating"]

            scan.status = "COMPLETED"
            scan.completed_at = completed_time
            scan.duration = round(duration_secs, 2)
            scan.resources_scanned = total_scanned
            scan.findings_count = len(active_findings)
            scan.critical_count = crit_c
            scan.high_count = high_c
            scan.medium_count = med_c
            scan.low_count = low_c
            scan.security_score = security_score
            scan.posture_rating = posture_rating
            scan.risk_summary = {
                "avg_risk": posture_data["avg_risk"],
                "max_risk": posture_data["max_risk"],
                "immediate_count": posture_data["immediate_count"],
                "high_priority_count": posture_data["high_priority_count"],
                "medium_priority_count": posture_data["medium_priority_count"],
                "low_priority_count": posture_data["low_priority_count"],
            }

            # Generate in-app notifications for scan completion and high/critical findings
            from app.services.notification_service import NotificationService
            NotificationService.create_scan_notifications(
                db=db,
                scan=scan,
                user_id=user.id,
                active_findings=active_findings,
                security_score=security_score,
            )

            # Audit log
            audit = AuditLog(
                user_id=user.id,
                action="SCAN_TRIGGERED",
                resource_type="scan",
                resource_id=str(scan.id),
                result="SUCCESS",
                metadata_json={
                    "cloud_account_id": str(account.id),
                    "account_identifier": account.account_identifier,
                    "resources_scanned": total_scanned,
                    "security_score": security_score,
                },
                ip_address=client_ip,
            )
            db.add(audit)
            db.commit()
            db.refresh(scan)

            logger.info(f"Scan {scan.id} completed successfully: {total_scanned} resources scanned, score: {security_score}%.")
            return scan

        except Exception as e:
            logger.error(f"Scan {scan.id} failed with error: {str(e)}", exc_info=True)
            db.rollback()
            try:
                target_scan = db.query(Scan).filter(Scan.id == scan.id).first()
                if target_scan:
                    target_scan.status = "FAILED"
                    target_scan.completed_at = utc_now()
                    target_scan.error_message = f"Scanner error: {str(e)}"
                    db.commit()
                    db.refresh(target_scan)
                    scan = target_scan
                else:
                    scan.status = "FAILED"
                    scan.completed_at = utc_now()
                    scan.error_message = f"Scanner error: {str(e)}"
                    db.commit()
            except Exception as update_err:
                db.rollback()
                logger.error(f"Failed to record FAILED status for scan {scan.id}: {update_err}")

            try:
                audit = AuditLog(
                    user_id=user.id,
                    action="SCAN_TRIGGERED",
                    resource_type="scan",
                    resource_id=str(scan.id),
                    result="FAILURE",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "error": str(e),
                    },
                    ip_address=client_ip,
                )
                db.add(audit)
                db.commit()
            except Exception as audit_err:
                db.rollback()
                logger.error(f"Failed to record failure audit log for scan {scan.id}: {audit_err}")

            return scan

    @staticmethod
    def get_scans(
        db: Session,
        account_id: Optional[uuid.UUID] = None,
        limit: int = 50,
        offset: int = 0,
        user: Optional[User] = None,
    ) -> Tuple[List[Scan], int]:
        """Returns paginated scan history and total count, scoped by user ownership."""
        from app.api.deps import is_admin, get_user_accessible_account_ids
        query = db.query(Scan)
        
        if user and not is_admin(user):
            accessible_ids = get_user_accessible_account_ids(db, user)
            query = query.filter(Scan.cloud_account_id.in_(accessible_ids))

        if account_id:
            query = query.filter(Scan.cloud_account_id == account_id)
        
        total = query.count()
        items = query.order_by(desc(Scan.created_at)).offset(offset).limit(limit).all()
        return items, total

    @staticmethod
    def get_scan_by_id(db: Session, scan_id: uuid.UUID, user: Optional[User] = None) -> Optional[Scan]:
        """Retrieves a single scan record with execution metrics and user isolation."""
        from app.api.deps import is_admin
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        if user and not is_admin(user):
            if scan.cloud_account and scan.cloud_account.user_id is not None and scan.cloud_account.user_id != user.id:
                return None
        return scan

    @staticmethod
    def get_resources(
        db: Session,
        account_id: Optional[uuid.UUID] = None,
        scan_id: Optional[uuid.UUID] = None,
        provider: Optional[str] = None,
        service: Optional[str] = None,
        security_status: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        user: Optional[User] = None,
    ) -> Tuple[List[Resource], int]:
        """Returns paginated cloud resource inventory with multi-criteria filtering and user isolation."""
        from app.api.deps import is_admin, get_user_accessible_account_ids
        query = db.query(Resource)

        if user and not is_admin(user):
            accessible_ids = get_user_accessible_account_ids(db, user)
            query = query.filter(Resource.cloud_account_id.in_(accessible_ids))

        # If account_id is not provided and no scan_id or provider filter, resolve based on current CSPM mode
        if not account_id and not scan_id and not provider:
            if user and not is_admin(user):
                user_acc = db.query(CloudAccount).filter(CloudAccount.user_id == user.id, CloudAccount.is_active == True).first()
                if user_acc:
                    account_id = user_acc.id

            if not account_id:
                if settings.CSPM_MODE.lower() == "aws":
                    aws_acc = db.query(CloudAccount).filter(CloudAccount.provider == "AWS", CloudAccount.is_active == True).first()
                    if aws_acc:
                        account_id = aws_acc.id
                elif settings.CSPM_MODE.lower() == "mock":
                    demo_acc = db.query(CloudAccount).filter(CloudAccount.provider == "MOCK").first()
                    if demo_acc:
                        account_id = demo_acc.id

        if account_id:
            query = query.filter(Resource.cloud_account_id == account_id)
        if scan_id:
            query = query.filter(Resource.scan_id == scan_id)
        if provider:
            query = query.filter(Resource.provider == provider.upper())
        if service:
            query = query.filter(Resource.service == service.upper())
        if security_status:
            query = query.filter(Resource.security_status == security_status.upper())
        if search:
            search_pattern = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    Resource.resource_id.ilike(search_pattern),
                    Resource.resource_name.ilike(search_pattern),
                    Resource.resource_type.ilike(search_pattern),
                )
            )

        total = query.count()
        items = query.order_by(Resource.service, Resource.resource_name).offset(offset).limit(limit).all()
        return items, total

    @staticmethod
    def get_resource_by_id(db: Session, resource_id: uuid.UUID, user: Optional[User] = None) -> Optional[Resource]:
        """Retrieves full configuration details and tags for a discovered asset with user isolation."""
        from app.api.deps import is_admin
        res = db.query(Resource).filter(Resource.id == resource_id).first()
        if not res:
            return None
        if user and not is_admin(user):
            if res.cloud_account and res.cloud_account.user_id is not None and res.cloud_account.user_id != user.id:
                return None
        return res

    @staticmethod
    def compare_scan_by_id(db: Session, scan_id: uuid.UUID, user: Optional[User] = None) -> Dict[str, Any]:
        """Compares a specific scan against its immediate predecessor for the same cloud account with user isolation."""
        from app.api.deps import is_admin
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID '{scan_id}' not found.")
        if user and not is_admin(user):
            if scan.cloud_account and scan.cloud_account.user_id is not None and scan.cloud_account.user_id != user.id:
                raise ValueError(f"Scan with ID '{scan_id}' not found.")

        return RiskScoringService.compare_scans(db=db, current_scan=scan)

    @staticmethod
    def get_dashboard_stats(db: Session, account_id: Optional[uuid.UUID] = None, user: Optional[User] = None) -> Dict[str, Any]:
        """
        Gathers complete, authentic security posture metrics for the SOC dashboard with user isolation.
        Returns live posture score, rating, risk distribution, priority distribution,
        score trend, top riskiest resources, and highest-risk findings.
        """
        from app.models.finding import Finding, SecurityRule
        from app.api.deps import is_admin, get_user_accessible_account_ids

        accessible_ids = None
        if user and not is_admin(user):
            accessible_ids = get_user_accessible_account_ids(db, user)

        # Resolve account based on mode if not explicitly provided
        if not account_id:
            if user and not is_admin(user):
                user_acc = db.query(CloudAccount).filter(CloudAccount.user_id == user.id, CloudAccount.is_active == True).first()
                if user_acc:
                    account_id = user_acc.id
                else:
                    demo_acc = db.query(CloudAccount).filter(CloudAccount.user_id.is_(None), CloudAccount.is_active == True).first()
                    if demo_acc:
                        account_id = demo_acc.id
            else:
                if settings.CSPM_MODE.lower() == "aws":
                    aws_acc = db.query(CloudAccount).filter(CloudAccount.provider == "AWS", CloudAccount.is_active == True).first()
                    if aws_acc:
                        account_id = aws_acc.id
                if not account_id:
                    demo_acc = db.query(CloudAccount).filter(CloudAccount.provider == "MOCK").first()
                    account_id = demo_acc.id if demo_acc else None

        # Fetch latest completed scan
        scan_query = db.query(Scan).filter(Scan.status == "COMPLETED")
        if accessible_ids is not None:
            scan_query = scan_query.filter(Scan.cloud_account_id.in_(accessible_ids))
        if account_id:
            scan_query = scan_query.filter(Scan.cloud_account_id == account_id)
        latest_scan = scan_query.order_by(desc(Scan.created_at)).first()

        # Score trends from last 10 scans
        history_scans = (
            scan_query.order_by(desc(Scan.created_at)).limit(10).all()
        )
        history_scans.reverse()
        score_trend = [
            {
                "id": str(s.id),
                "date": s.completed_at.isoformat() if s.completed_at else s.created_at.isoformat(),
                "score": s.security_score or 0.0,
                "rating": s.posture_rating or "GOOD",
                "findings": s.findings_count,
            }
            for s in history_scans
        ]

        # Top 5 highest risk open findings
        findings_query = db.query(Finding).join(SecurityRule).join(Resource).filter(Finding.status == "OPEN")
        if accessible_ids is not None:
            findings_query = findings_query.filter(Finding.cloud_account_id.in_(accessible_ids))
        if account_id:
            findings_query = findings_query.filter(Finding.cloud_account_id == account_id)
        top_findings_raw = (
            findings_query.order_by(desc(Finding.risk_score), desc(Finding.created_at)).limit(5).all()
        )
        top_findings = [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "risk_level": f.risk_level,
                "risk_priority": f.risk_priority,
                "rule_code": f.rule.rule_id if f.rule else None,
                "service": f.resource.service if f.resource else None,
                "resource_name": f.resource.resource_name if f.resource else None,
                "resource_identifier": f.resource.resource_id if f.resource else None,
                "explanation": f.risk_explanation,
            }
            for f in top_findings_raw
        ]

        # Top 5 riskiest resources (at risk or critical)
        res_query = db.query(Resource)
        if accessible_ids is not None:
            res_query = res_query.filter(Resource.cloud_account_id.in_(accessible_ids))
        if account_id:
            res_query = res_query.filter(Resource.cloud_account_id == account_id)
        all_resources = res_query.all()

        risky_resources = []
        for r in all_resources:
            r_findings = [f for f in r.findings if f.status == "OPEN"]
            if r_findings:
                max_f_risk = max(f.risk_score for f in r_findings)
                risky_resources.append({
                    "id": str(r.id),
                    "resource_id": r.resource_id,
                    "resource_name": r.resource_name or r.resource_id,
                    "service": r.service,
                    "resource_type": r.resource_type,
                    "security_status": r.security_status,
                    "open_findings_count": len(r_findings),
                    "highest_risk_score": max_f_risk,
                })
        risky_resources.sort(key=lambda x: x["highest_risk_score"], reverse=True)
        top_risky_resources = risky_resources[:5]

        # Historical comparison
        comparison = (
            RiskScoringService.compare_scans(db=db, current_scan=latest_scan)
            if latest_scan
            else {
                "has_previous_scan": False,
                "score_change": 0.0,
                "risk_change": 0.0,
                "new_findings": 0,
                "resolved_findings": 0,
                "persistent_findings": 0,
            }
        )

        # Baseline stats
        security_score = latest_scan.security_score if latest_scan else 100.0
        posture_rating = latest_scan.posture_rating if latest_scan else "EXCELLENT"
        risk_summary = latest_scan.risk_summary if latest_scan else {}

        return {
            "latest_scan_id": str(latest_scan.id) if latest_scan else None,
            "security_score": security_score,
            "posture_rating": posture_rating,
            "total_resources": latest_scan.resources_scanned if latest_scan else len(all_resources),
            "total_findings": latest_scan.findings_count if latest_scan else len(top_findings_raw),
            "severity_distribution": {
                "critical": latest_scan.critical_count if latest_scan else 0,
                "high": latest_scan.high_count if latest_scan else 0,
                "medium": latest_scan.medium_count if latest_scan else 0,
                "low": latest_scan.low_count if latest_scan else 0,
            },
            "priority_distribution": {
                "immediate": risk_summary.get("immediate_count", 0),
                "high": risk_summary.get("high_priority_count", 0),
                "medium": risk_summary.get("medium_priority_count", 0),
                "low": risk_summary.get("low_priority_count", 0),
            },
            "risk_metrics": {
                "avg_risk": risk_summary.get("avg_risk", 0.0),
                "max_risk": risk_summary.get("max_risk", 0),
            },
            "score_trend": score_trend,
            "top_findings": top_findings,
            "top_risky_resources": top_risky_resources,
            "comparison": comparison,
        }
