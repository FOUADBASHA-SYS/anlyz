"""
Main FastAPI Application for Cloud XDR URL Threat Analyzer.
Integrates modular routers, middleware, static files, and initial admin bootstrap.
"""
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.database import engine, Base, SessionLocal
from backend.models import User
from backend.security import hash_password
from backend.services.watchlist_service import start_scheduler, stop_scheduler
from backend.routers import (
    auth, scans, bulk, watchlists, rules, dashboard, feedback, chat, tokens, admin
)
from analyzer import UnsafeURL

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("xdr.app")


def bootstrap_admin():
    """Initializes default administrator account if database has no admin."""
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.role == "admin").first()
        if not admin_user:
            logger.info("No administrator found. Creating initial admin: %s", settings.INITIAL_ADMIN_EMAIL)
            new_admin = User(
                email=settings.INITIAL_ADMIN_EMAIL.lower().strip(),
                hashed_password=hash_password(settings.INITIAL_ADMIN_PASSWORD),
                role="admin",
                is_active=True,
                is_approved=True,
            )
            db.add(new_admin)
            db.commit()
            logger.info("Initial administrator account created.")
    except Exception as e:
        logger.error("Failed to bootstrap administrator account: %s", e)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure tables exist and start scheduler
    Base.metadata.create_all(bind=engine)
    bootstrap_admin()
    start_scheduler()
    logger.info("URL Analyzer Application started successfully.")
    yield
    # Shutdown
    stop_scheduler()
    logger.info("URL Analyzer Application shut down.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Enhanced Cloud XDR Platform - URL Threat Sandbox & Analysis Engine",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/api/v1/openapi.json",
)

# CORS Middleware (restricted in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else ["http://localhost:5000", "http://127.0.0.1:5000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Centralized Error Handlers
@app.exception_handler(UnsafeURL)
async def unsafe_url_exception_handler(request: Request, exc: UnsafeURL):
    logger.warning("SSRF/UnsafeURL gate rejected request: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": str(exc), "detail": "SSRF gatekeeper blocked access to non-public/internal address."}
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled server exception at %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "An internal server error occurred.", "detail": str(exc) if settings.DEBUG else None}
    )


# Health check
@app.get("/health", tags=["Health"])
@app.get("/api/v1/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT
    }


# Include Routers
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(bulk.router)
app.include_router(watchlists.router)
app.include_router(rules.router)
app.include_router(dashboard.router)
app.include_router(feedback.router)
app.include_router(chat.router)
app.include_router(tokens.router)
app.include_router(admin.router)

# Mount Static Files and Root Dashboard
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(os.path.join(static_dir, "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=5000, reload=settings.DEBUG)
