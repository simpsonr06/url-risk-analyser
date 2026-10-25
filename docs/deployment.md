# Deployment Guide

This guide details deployment options for the **URL Risk Analyser**, focusing on low-cost, containerized environments supporting persistent SQLite storage.

---

## Deployment Strategy & Target Comparison

| Platform | Tier / Cost | SQLite Persistence | RDAP Egress | Operational Complexity | Recommendation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Fly.io** | Free allowance / Low cost | Yes (Fly Volumes) | Full Outbound | Minimal (Dockerfile) | **Primary Choice** |
| **Render** | Free / Starter | Yes (Persistent Disks) | Full Outbound | Minimal (Docker / Native) | **Secondary Choice** |
| **Railway** | Starter usage | Yes (Volume Mounts) | Full Outbound | Minimal (Docker) | Viable Alternative |
| **Self-Hosted VPS** | $3–5/mo | Yes (Local Disk) | Full Outbound | Low (Docker Compose) | Great for homelab / dedicated VPS |

---

## Option 1: Docker / Docker Compose (Local or VPS)

### Building the Image

```bash
docker build -t url-risk-analyser:latest .
```

### Running with Persistent Volume

```bash
docker run -d \
  --name url-risk-analyser \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -e ENV=production \
  -e DATABASE_PATH=/app/data/phishing_platform.db \
  url-risk-analyser:latest
```

### Running with Docker Compose

```bash
docker compose up -d
```
Verify the health check:
```bash
docker inspect --format='{{json .State.Health.Status}}' url-risk-analyser
```

---

## Option 2: Deploying to Fly.io (Primary Target)

Fly.io provides native support for lightweight Docker containers with dedicated persistent storage volumes.

### Step-by-Step Instructions:

1. **Install Fly CLI & Authenticate:**
   ```bash
   fly auth login
   ```

2. **Initialize Fly App:**
   ```bash
   fly launch --no-deploy
   ```

3. **Create Persistent Storage Volume for SQLite:**
   ```bash
   fly volumes create phish_data --size 1 --region ord
   ```

4. **Attach Volume in `fly.toml`:**
   Add the following block to your generated `fly.toml`:
   ```toml
   [mounts]
     source = "phish_data"
     destination = "/app/data"

   [env]
     ENV = "production"
     DATABASE_PATH = "/app/data/phishing_platform.db"
   ```

5. **Deploy:**
   ```bash
   fly deploy
   ```

---

## Option 3: Deploying to Render

1. Create a new **Web Service** on Render connected to your Git repository.
2. Select **Docker** environment.
3. Attach a **Persistent Disk**:
   - Mount Path: `/app/data`
   - Size: 1 GB
4. Set Environment Variables:
   - `ENV`: `production`
   - `DATABASE_PATH`: `/app/data/phishing_platform.db`
   - `PORT`: `8000`
5. Deploy service.

---

## Verification After Deployment

Once deployed, verify your public instance:
1. `GET /health` returns `{"status": "healthy"}`.
2. `GET /` serves the dashboard.
3. `POST /api/scan` processes URLs and persists scan history across container restarts.
