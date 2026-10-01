# Backend image: FastAPI + Uvicorn (production, no --reload).
# Build context is the repository root: docker build -f backend/Dockerfile .
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the backend package (see .dockerignore for exclusions).
COPY backend/ ./backend/

# Writable location for the SQLite database file (mounted as a volume).
RUN mkdir -p /data

EXPOSE 8000

# DATABASE_URL is injected by Compose (sqlite file under /data).
# Tables are created before seeding because main.py (which also creates
# tables) is only imported when uvicorn starts. The seed is idempotent:
# it inserts rows only when missing.
CMD ["sh", "-c", "python -c 'from backend.app.core.database import engine; from backend.app.models.database import Base; Base.metadata.create_all(bind=engine); from backend.data.seeds.seed_data import create_seed_data; create_seed_data()' && exec uvicorn backend.app.main:app --host 0.0.0.0 --port 8000"]
