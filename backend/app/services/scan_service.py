import logging
import uuid
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_

from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import SecurityRule
from app.models.auth import User
from app.models.audit import AuditLog
from app.models.base import utc_now
from app.scanner.providers.mock.provider import MockProvider
from app.scanner.engine.scanner import ScannerEngine
from app.scanner.rules.executor import RuleExecutor
from app.services.finding_service import FindingService

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
        if account_id:
            account = db.query(CloudAccount).filter(CloudAccount.id == account_id).first()
            if not account:
                raise ValueError(f"Cloud account with ID {account_id} not found.")
        else:
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

            # Instantiate Provider & Engine
            # In Phase 4, if provider is MOCK or in mock mode, use MockProvider
            provider = MockProvider(
                account_id=account.account_identifier,
                default_region=account.default_region,
            )
            engine = ScannerEngine(provider=provider)

            # Run Discovery Pipeline
            discovered_items = engine.run_discovery_pipeline()

            # Upsert Resource records
            now = utc_now()
            scanned_resource_ids = set()
            for item in discovered_items:
                scanned_resource_ids.add(item.resource_id)
                existing_res = db.query(Resource).filter(
                    Resource.cloud_account_id == account.id,
                    Resource.resource_id == item.resource_id,
                ).first()

                if existing_res:
                    existing_res.scan_id = scan.id
                    existing_res.resource_name = item.resource_name
                    existing_res.region = item.region
                    existing_res.tags = item.tags
                    existing_res.configuration = item.configuration
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
                        tags=item.tags,
                        configuration=item.configuration,
                        security_status="UNKNOWN",
                        first_seen=now,
                        last_seen=now,
                    )
                    db.add(new_res)

            db.commit()

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

            # Tally metrics
            total_scanned = len(discovered_items)
            completed_time = utc_now()
            started = scan.started_at
            if started and started.tzinfo is None:
                started = started.replace(tzinfo=completed_time.tzinfo)
            duration_secs = (completed_time - started).total_seconds() if started else 0.0

            # Calculate posture score based on percentage of secure assets
            secure_assets_count = db.query(Resource).filter(
                Resource.cloud_account_id == account.id,
                Resource.security_status == "SECURE",
            ).count()
            security_score = round((secure_assets_count / total_scanned) * 100.0, 1) if total_scanned > 0 else 100.0

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
            scan.status = "FAILED"
            scan.completed_at = utc_now()
            scan.error_message = f"Scanner error: {str(e)}"
            
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
            db.refresh(scan)
            return scan

    @staticmethod
    def get_scans(
        db: Session,
        account_id: Optional[uuid.UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Scan], int]:
        """Returns paginated scan history and total count."""
        query = db.query(Scan)
        if account_id:
            query = query.filter(Scan.cloud_account_id == account_id)
        
        total = query.count()
        items = query.order_by(desc(Scan.created_at)).offset(offset).limit(limit).all()
        return items, total

    @staticmethod
    def get_scan_by_id(db: Session, scan_id: uuid.UUID) -> Optional[Scan]:
        """Retrieves a single scan record with execution metrics."""
        return db.query(Scan).filter(Scan.id == scan_id).first()

    @staticmethod
    def get_resources(
        db: Session,
        account_id: Optional[uuid.UUID] = None,
        service: Optional[str] = None,
        security_status: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Resource], int]:
        """Returns paginated cloud resource inventory with multi-criteria filtering."""
        query = db.query(Resource)

        if account_id:
            query = query.filter(Resource.cloud_account_id == account_id)
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
    def get_resource_by_id(db: Session, resource_id: uuid.UUID) -> Optional[Resource]:
        """Retrieves full configuration details and tags for a discovered asset."""
        return db.query(Resource).filter(Resource.id == resource_id).first()
