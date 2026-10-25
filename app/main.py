import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from config.settings import ALLOWED_ORIGINS, ENV, HOST, PORT, DATABASE_PATH
from app.routes.scan import router as scan_router

# Configure logging format
logging.basicConfig(
    level=logging.INFO if ENV == "production" else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishing_platform")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting Phishing Detection Platform [ENV={ENV}]")
    logger.info(f"Database Path: {DATABASE_PATH}")
    logger.info(f"Allowed CORS Origins: {ALLOWED_ORIGINS}")
    yield
    logger.info("Shutting down Phishing Detection Platform")

app = FastAPI(
    title="Intelligent Phishing Detection Platform API",
    description="Analyzes URLs to determine risk level via heuristics, entropy, and domain intelligence.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
allow_all = "*" in ALLOWED_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if allow_all else ALLOWED_ORIGINS,
    allow_credentials=False if allow_all else True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Health Check for container environments and uptime monitors
@app.get("/health", tags=["System"])
async def health_check():
    """Service health and liveness probe."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "environment": ENV
    }

# API Routes
app.include_router(scan_router, prefix="/api")

# Serve Frontend
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

@app.get("/", tags=["Frontend"])
async def serve_frontend():
    """Serve the single-page dashboard application."""
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse(status_code=404, content={"message": "Frontend not found"})
