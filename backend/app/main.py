from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import setup_logging
from app.api.health import router as health_router

logger = setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    logger.info(f"Execution Mode: {settings.CSPM_MODE.upper()}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    yield
    logger.info("Shutting down application...")


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

