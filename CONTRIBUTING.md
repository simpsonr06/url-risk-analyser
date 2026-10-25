# Contributing to URL Risk Analyser

Thank you for your interest in contributing to the **Intelligent Phishing Detection Platform & URL Risk Analyser**!

## Code of Conduct
Please ensure all discussions and contributions remain professional, constructive, and respectful.

---

## Local Development Setup

### 1. Clone & Set Up Virtual Environment

```bash
# Clone the repository
git clone https://github.com/your-username/url-risk-analyser.git
cd url-risk-analyser

# Create Python virtual environment
python -m venv .venv

# Activate on Windows:
.venv\Scripts\activate

# Activate on Linux / macOS:
source .venv/bin/activate
```

### 2. Install Dependencies

```bash
# Production dependencies
pip install -r requirements.txt

# Development and testing dependencies
pip install -r requirements-dev.txt
```

### 3. Run the Development Server

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open your browser at `http://127.0.0.1:8000/`.

---

## Testing & Quality Assurance

All pull requests must pass the automated test suite before merging.

```bash
# Run pytest test suite
pytest -v

# Run tests with detailed traceback on failure
pytest -v --tb=short
```

### Verification Guidelines
- Keep tests isolated; never configure tests to modify `phishing_platform.db`.
- Mock external network calls to RDAP registry services.
- Ensure regression tests accompany any newly introduced heuristic rules or security patches.

---

## Submitting Pull Requests

1. Create a feature branch: `git checkout -b feature/your-feature-name`.
2. Commit changes with clear, descriptive commit messages.
3. Push to your fork: `git push origin feature/your-feature-name`.
4. Open a Pull Request targeting `main`.
