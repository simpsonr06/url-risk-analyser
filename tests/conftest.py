import os
import tempfile
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Set environment to testing before importing app components
os.environ["ENV"] = "testing"
os.environ["RATE_LIMIT_ENABLED"] = "true"
os.environ["RATE_LIMIT_PER_MINUTE"] = "10"

from config import settings
from database.db import init_db, get_db_connection
from app.main import app
from app.limiter import reset_rate_limits

@pytest.fixture(scope="session", autouse=True)
def configure_test_environment():
    """Ensure test settings point to a disposable test database."""
    temp_dir = tempfile.mkdtemp(prefix="phish_test_")
    test_db_path = os.path.join(temp_dir, "test_scans.db")
    settings.DATABASE_PATH = test_db_path
    settings.DATABASE_URL = test_db_path
    init_db(test_db_path)
    yield test_db_path
    # Teardown
    try:
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)
    except Exception:
        pass

@pytest.fixture(autouse=True)
def reset_limits():
    """Reset rate limiter state before each test."""
    reset_rate_limits()

@pytest.fixture
def test_db(configure_test_environment):
    """Provide a fresh or managed test database connection."""
    db_path = configure_test_environment
    conn = get_db_connection(db_path)
    yield conn
    conn.close()

@pytest_asyncio.fixture
async def async_client():
    """Async HTTP test client bound to FastAPI ASGI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
