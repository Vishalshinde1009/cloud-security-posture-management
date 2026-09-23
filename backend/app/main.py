from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import setup_logging
from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.resources import router as resources_router
from app.api.findings import router as findings_router
from app.api.rules import router as rules_router
from app.api.dashboard import router as dashboard_router
from app.api.cloud_accounts import router as cloud_accounts_router
from app.api.compliance import router as compliance_router
from app.api.notifications import router as notifications_router
from app.api.reports import router as reports_router
from app.api.audit import router as audit_router
from app.api.monitoring import router as monitoring_router
from app.api.alerts import router as alerts_router

logger = setup_logging()

# Module-level scheduler instance — created once, shared across lifespan
_monitoring_scheduler = None



@asynccontextmanager
async def lifespan(app: FastAPI):
    global _monitoring_scheduler
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    logger.info(f"Execution Mode: {settings.CSPM_MODE.upper()}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")

    # Phase 9B: Start background monitoring scheduler (only if enabled)
    if settings.CSPM_MONITORING_ENABLED:
        from app.database.session import SessionLocal
        from app.monitoring.scheduler import MonitoringScheduler
        _monitoring_scheduler = MonitoringScheduler(db_session_factory=SessionLocal)
        _monitoring_scheduler.start()
        logger.info("Continuous monitoring scheduler started.")
    else:
        logger.info("Continuous monitoring scheduler disabled (CSPM_MONITORING_ENABLED=false).")

    yield

    logger.info("Shutting down application...")
    if _monitoring_scheduler is not None:
        _monitoring_scheduler.stop(timeout=10.0)
        logger.info("Continuous monitoring scheduler stopped.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Automated Cloud Misconfiguration Detection and Risk Assessment Platform",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security HTTP Headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Include Routers - accessible at both /health and /api/health
app.include_router(health_router)
app.include_router(health_router, prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(scans_router, prefix=settings.API_V1_STR)
app.include_router(resources_router, prefix=settings.API_V1_STR)
app.include_router(findings_router, prefix=settings.API_V1_STR)
app.include_router(rules_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(cloud_accounts_router, prefix=settings.API_V1_STR)
app.include_router(compliance_router, prefix=settings.API_V1_STR)
app.include_router(notifications_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(audit_router, prefix=settings.API_V1_STR)
app.include_router(monitoring_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)



@app.get(f"{settings.API_V1_STR}/docs", include_in_schema=False)
def get_api_docs_redirect():
    return RedirectResponse(url="/docs")


@app.get(f"{settings.API_V1_STR}/redoc", include_in_schema=False)
def get_api_redoc_redirect():
    return RedirectResponse(url="/redoc")


@app.get(f"{settings.API_V1_STR}/openapi.json", include_in_schema=False)
def get_api_openapi_redirect():
    return RedirectResponse(url="/openapi.json")


@app.get("/")
def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "docs": "/docs",
        "health": "/health",
        "mode": settings.CSPM_MODE,
    }

