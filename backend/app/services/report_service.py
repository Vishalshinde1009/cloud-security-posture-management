"""
Report Generation Service using ReportLab.
Produces professional executive & technical PDF posture reports from real database scan metrics.
Prevents secret exposure, validates file paths, and provides secure downloadable report artifacts.
"""

import os
import uuid
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable

from app.models.report import Report
from app.models.cloud import Scan, CloudAccount
from app.models.finding import Finding
from app.models.base import utc_now
from app.services.compliance_service import ComplianceService

logger = logging.getLogger("cspm.services.reports")

REPORTS_DIR = Path("data/reports").resolve()


class ReportService:
    @staticmethod
    def ensure_reports_dir() -> Path:
        """Ensures the secure reports storage directory exists."""
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        return REPORTS_DIR

    @staticmethod
    def get_report_file_path(report: Report) -> Optional[Path]:
        """
        Validates and returns the safe file path for a report.
        Strictly prevents directory traversal by verifying the path resides within REPORTS_DIR.
        """
        if not report.file_reference:
            return None

        file_path = (REPORTS_DIR / report.file_reference).resolve()
        # Path traversal guard
        if not str(file_path).startswith(str(REPORTS_DIR)):
            logger.error(f"Security Alert: Path traversal attempt detected for report {report.id}: {report.file_reference}")
            raise PermissionError("Access denied: Invalid report file path reference.")

        if not file_path.exists():
            return None

        return file_path

    @staticmethod
    def generate_posture_report(
        db: Session,
        scan_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
        report_type: str = "EXECUTIVE_POSTURE",
    ) -> Report:
        """
        Compiles real database scan data and renders a professional, multi-page PDF report.
        Never includes sensitive credentials, passwords, or session tokens.
        """
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found.")

        account = scan.cloud_account
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).order_by(desc(Finding.risk_score)).all()

        # Compliance overview
        compliance_summaries = ComplianceService.get_all_frameworks_overview(db, account_id=account.id if account else None)

        # Initialize Report record
        report_id = uuid.uuid4()
        filename = f"CSPM_Posture_Report_{scan.id}_{report_id.hex[:8]}.pdf"
        ReportService.ensure_reports_dir()
        pdf_path = REPORTS_DIR / filename

        report = Report(
            id=report_id,
            scan_id=scan.id,
            generated_by=user_id,
            report_type=report_type,
            file_reference=filename,
            status="GENERATING",
            created_at=utc_now(),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        try:
            ReportService._render_pdf(
                output_path=str(pdf_path),
                scan=scan,
                account=account,
                findings=findings,
                compliance_summaries=compliance_summaries,
                report_id=report_id,
            )
            report.status = "COMPLETED"
            db.commit()
            db.refresh(report)
            logger.info(f"Successfully generated PDF report {report.id} at {pdf_path}")
            return report
        except Exception as e:
            report.status = "FAILED"
            db.commit()
            logger.error(f"Failed to generate PDF report {report.id}: {e}", exc_info=True)
            raise

    @staticmethod
    def _render_pdf(
        output_path: str,
        scan: Scan,
        account: Optional[CloudAccount],
        findings: List[Finding],
        compliance_summaries: List[Dict[str, Any]],
        report_id: uuid.UUID,
    ) -> None:
        """Renders the styled PDF layout using ReportLab."""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()

        # Custom Palette
        c_primary = colors.HexColor("#1E3A8A")     # Dark Blue
        c_secondary = colors.HexColor("#0284C7")   # Light Blue
        c_dark = colors.HexColor("#0F172A")        # Slate 900
        c_gray = colors.HexColor("#64748B")        # Slate 500
        c_light = colors.HexColor("#F8FAFC")       # Slate 50
        c_border = colors.HexColor("#CBD5E1")      # Slate 300
        c_critical = colors.HexColor("#DC2626")    # Red
        c_high = colors.HexColor("#EA580C")        # Orange
        c_medium = colors.HexColor("#D97706")      # Amber
        c_low = colors.HexColor("#10B981")         # Emerald

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=c_primary,
            spaceAfter=4,
        )

        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=14,
            textColor=c_gray,
            spaceAfter=15,
        )

        h1_style = ParagraphStyle(
            "H1",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=c_dark,
            spaceBefore=12,
            spaceAfter=6,
        )

        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=c_dark,
        )

        small_style = ParagraphStyle(
            "Small",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=c_gray,
        )

        story = []

        # =====================================================================
        # Header Banner
        # =====================================================================
        story.append(Paragraph("CLOUD SECURITY POSTURE ASSESSMENT REPORT", title_style))
        story.append(Paragraph(f"Autonomous CSPM Analysis &bull; Report ID: {str(report_id)[:8]} &bull; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=c_primary, spaceBefore=0, spaceAfter=15))

        # =====================================================================
        # Executive Summary & Metadata Table
        # =====================================================================
        account_name = account.name if account else "Default Cloud Account"
        account_id = account.account_identifier if account else "N/A"
        provider = account.provider if account else "AWS"
        score = scan.security_score or 0
        rating = scan.posture_rating or "PENDING"

        meta_data = [
            [
                Paragraph("<b>Target Account:</b>", body_style),
                Paragraph(account_name, body_style),
                Paragraph("<b>Provider:</b>", body_style),
                Paragraph(f"{provider} (Read-Only)", body_style),
            ],
            [
                Paragraph("<b>Account Identifier:</b>", body_style),
                Paragraph(account_id, body_style),
                Paragraph("<b>Scan Identifier:</b>", body_style),
                Paragraph(str(scan.id)[:12] + "...", body_style),
            ],
            [
                Paragraph("<b>Assets Audited:</b>", body_style),
                Paragraph(str(scan.resources_scanned), body_style),
                Paragraph("<b>Findings Detected:</b>", body_style),
                Paragraph(str(scan.findings_count), body_style),
            ],
            [
                Paragraph("<b>Posture Rating:</b>", body_style),
                Paragraph(f"<b>{rating}</b>", body_style),
                Paragraph("<b>Overall Security Score:</b>", body_style),
                Paragraph(f"<b>{score} / 100</b>", body_style),
            ],
        ]

        meta_table = Table(meta_data, colWidths=[110, 160, 110, 150])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c_light),
            ("BOX", (0, 0), (-1, -1), 1, c_border),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 15))

        # =====================================================================
        # Severity & Risk Factor Distribution
        # =====================================================================
        story.append(Paragraph("1. Risk & Severity Breakdown", h1_style))

        sev_data = [
            ["Severity", "Count", "Priority Level", "Recommended SLA"],
            ["CRITICAL", str(scan.critical_count), "Immediate", "24 Hours"],
            ["HIGH", str(scan.high_count), "High", "7 Days"],
            ["MEDIUM", str(scan.medium_count), "Medium", "30 Days"],
            ["LOW", str(scan.low_count), "Low", "90 Days"],
        ]

        sev_table = Table(sev_data, colWidths=[120, 100, 150, 160])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_dark),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOX", (0, 0), (-1, -1), 1, c_border),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
            ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#FEE2E2")),
            ("BACKGROUND", (0, 2), (0, 2), colors.HexColor("#FFEDD5")),
            ("BACKGROUND", (0, 3), (0, 3), colors.HexColor("#FEF3C7")),
            ("BACKGROUND", (0, 4), (0, 4), colors.HexColor("#D1FAE5")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 15))

        # =====================================================================
        # Compliance Alignment Summary
        # =====================================================================
        story.append(Paragraph("2. Security Control Framework Alignment", h1_style))
        story.append(Paragraph(
            "<i>Note: Calculations denote security-control baseline alignment and gap coverage. "
            "They do not constitute formal regulatory compliance certification.</i>",
            small_style,
        ))
        story.append(Spacer(1, 6))

        comp_data = [["Security Framework", "Controls Assessed", "Passing", "Failing", "Alignment %"]]
        for cs in compliance_summaries:
            comp_data.append([
                cs["framework_name"],
                str(cs["assessed_controls"]),
                str(cs["passing_controls"]),
                str(cs["failing_controls"]),
                f"{cs['coverage_percentage']}%",
            ])

        comp_table = Table(comp_data, colWidths=[190, 90, 80, 80, 90])
        comp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_primary),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOX", (0, 0), (-1, -1), 1, c_border),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(comp_table)
        story.append(Spacer(1, 15))

        # =====================================================================
        # Top Critical & High Risk Findings
        # =====================================================================
        story.append(Paragraph("3. Prioritized Security Findings (Top Violations)", h1_style))

        top_findings = findings[:8]
        if not top_findings:
            story.append(Paragraph("No open security findings detected for this scan.", body_style))
        else:
            findings_data = [["Severity", "Finding Title", "Asset ID", "Risk Score", "Status"]]
            for f in top_findings:
                res_id = f.resource.resource_id if f.resource else "Global"
                findings_data.append([
                    f.severity,
                    Paragraph(f.title[:45], body_style),
                    Paragraph(res_id[:25], small_style),
                    f"{round(f.risk_score, 1)}",
                    f.status,
                ])

            f_table = Table(findings_data, colWidths=[70, 210, 130, 60, 60])
            f_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), c_dark),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 1, c_border),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, c_border),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(f_table)

        story.append(Spacer(1, 15))

        # =====================================================================
        # Remediation Guidance & Disclaimer
        # =====================================================================
        story.append(Paragraph("4. Recommended Immediate Remediation Actions", h1_style))
        remediation_items = [
            "&bull; <b>S3 Buckets:</b> Enforce S3 Block Public Access across all buckets and enable SSE-S3 or SSE-KMS default encryption.",
            "&bull; <b>IAM Security:</b> Enforce Multi-Factor Authentication (MFA) on all console users and deactivate access keys older than 90 days.",
            "&bull; <b>Network Perimeter:</b> Eliminate 0.0.0.0/0 ingress rules on management ports (SSH 22, RDP 3389) and databases.",
            "&bull; <b>Logging & Auditing:</b> Ensure CloudTrail is enabled across all regions with cryptographic log file validation active.",
            "&bull; <b>Databases:</b> Ensure Amazon RDS instances are not publicly accessible and enforce KMS storage encryption at rest.",
        ]
        for rem in remediation_items:
            story.append(Paragraph(rem, body_style))
            story.append(Spacer(1, 3))

        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=0.5, color=c_border, spaceBefore=0, spaceAfter=8))
        doc.build(story)

    @staticmethod
    def generate_report(
        db: Session,
        user: Any,
        account_id: Optional[uuid.UUID] = None,
        report_type: str = "EXECUTIVE",
        title: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        High-level wrapper to trigger and persist an Executive or Technical PDF report.
        Identifies latest completed scan and compiles metrics.
        """
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

        scan_query = db.query(Scan).filter(Scan.status == "COMPLETED")
        if accessible_ids is not None:
            scan_query = scan_query.filter(Scan.cloud_account_id.in_(accessible_ids))
        if account_id:
            scan_query = scan_query.filter(Scan.cloud_account_id == account_id)
        latest_scan = scan_query.order_by(desc(Scan.created_at)).first()

        if not latest_scan:
            raise ValueError("No completed scan found. Please run a security scan before generating reports.")

        rep = ReportService.generate_posture_report(
            db=db,
            scan_id=latest_scan.id,
            user_id=user.id,
            report_type=report_type.upper(),
        )

        file_path_obj = ReportService.get_report_file_path(rep)
        return {
            "id": rep.id,
            "cloud_account_id": latest_scan.cloud_account_id,
            "title": title or f"{report_type.capitalize()} Posture Report - {latest_scan.created_at.strftime('%Y-%m-%d')}",
            "report_type": rep.report_type,
            "format": "PDF",
            "file_path": str(file_path_obj) if file_path_obj else None,
            "created_at": rep.created_at,
        }

    @staticmethod
    def list_reports(
        db: Session,
        account_id: Optional[uuid.UUID] = None,
        limit: int = 50,
        offset: int = 0,
        user: Optional[Any] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Lists generated reports with metadata and user isolation."""
        from app.core.config import settings
        from app.api.deps import is_admin, get_user_accessible_account_ids

        query = db.query(Report).join(Scan)

        if user and not is_admin(user):
            accessible_ids = get_user_accessible_account_ids(db, user)
            query = query.filter(Scan.cloud_account_id.in_(accessible_ids))

        if not account_id:
            if not user or is_admin(user):
                if settings.CSPM_MODE.lower() == "aws":
                    aws_acc = db.query(CloudAccount).filter(CloudAccount.provider == "AWS", CloudAccount.is_active == True).first()
                    if aws_acc:
                        account_id = aws_acc.id
                elif settings.CSPM_MODE.lower() == "mock":
                    demo_acc = db.query(CloudAccount).filter(CloudAccount.provider == "MOCK").first()
                    if demo_acc:
                        account_id = demo_acc.id
            else:
                user_acc = db.query(CloudAccount).filter(CloudAccount.user_id == user.id, CloudAccount.is_active == True).first()
                if user_acc:
                    account_id = user_acc.id

        if account_id:
            query = query.filter(Scan.cloud_account_id == account_id)

        total = query.count()
        reports = query.order_by(desc(Report.created_at)).offset(offset).limit(limit).all()

        items = []
        for r in reports:
            fp = ReportService.get_report_file_path(r)
            items.append({
                "id": r.id,
                "cloud_account_id": r.scan.cloud_account_id if r.scan else None,
                "title": f"{r.report_type.capitalize()} Posture Assessment",
                "report_type": r.report_type,
                "format": "PDF",
                "file_path": str(fp) if fp else None,
                "created_at": r.created_at,
            })
        return items, total

    @staticmethod
    def get_report_by_id(db: Session, report_id: uuid.UUID, user: Optional[Any] = None) -> Optional[Any]:
        """Retrieves report by ID with user isolation."""
        from app.api.deps import is_admin
        r = db.query(Report).filter(Report.id == report_id).first()
        if not r:
            return None
        if user and not is_admin(user):
            is_owner = False
            if r.generated_by == user.id:
                is_owner = True
            elif r.scan and r.scan.cloud_account and r.scan.cloud_account.user_id == user.id:
                is_owner = True
            if not is_owner:
                return None

        fp = ReportService.get_report_file_path(r)
        
        class ReportProxy:
            def __init__(self, rep, path):
                self.id = rep.id
                self.cloud_account_id = rep.scan.cloud_account_id if rep.scan else None
                self.title = f"{rep.report_type.capitalize()} Posture Assessment"
                self.report_type = rep.report_type
                self.format = "PDF"
                self.file_path = str(path) if path else None
                self.created_at = rep.created_at
                
        return ReportProxy(r, fp)

