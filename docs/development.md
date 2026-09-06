# Development Guide (Phase 1 Baseline)

## 1. Prerequisites
- **Python**: 3.11 or higher (tested on 3.11, 3.12, 3.13)
- **Node.js**: v18.0.0 or higher (v20+ recommended)
- **Package Managers**: `pip` and `npm`
- **Git**: 2.30+

---

## 2. Environment Setup

### 2.1 Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   # Windows (PowerShell):
   .venv\Scripts\Activate.ps1
   # Linux / macOS:
   source .venv/bin/activate
   ```
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy the environment configuration file:
   ```bash
   cd ..
   cp .env.example .env
   ```

### 2.2 Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```

---

## 3. Running Services Locally

### 3.1 Backend Server
```bash
cd backend
uvicorn app.main:app --reload --port 8000
```
- API Root: `http://127.0.0.1:8000/`
- Healthcheck: `http://127.0.0.1:8000/health` (or `http://127.0.0.1:8000/api/health`)
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc UI: `http://127.0.0.1:8000/redoc`

### 3.2 Frontend Development Server
```bash
cd frontend
npm run dev
```
- Local dashboard URL: `http://localhost:5173`
- The Vite development server automatically proxies `/api` requests to `http://127.0.0.1:8000`.

---

## 4. Testing & Verification

### 4.1 Backend Automated Tests
Execute the pytest suite from the project root:
```bash
backend/.venv/Scripts/python.exe -m pytest backend/tests
```
Test files:
- `backend/tests/test_health.py`: Verifies `/`, `/health`, `/api/health`, `/docs`, `/redoc`, `/openapi.json`, and security response headers.

### 4.2 Frontend Build & TypeScript Check
Run the TypeScript compiler and Vite production bundler:
```bash
cd frontend
npm run build
```
Build output is generated under `frontend/dist/`.

---

## 5. Coding Standards & Conventions
- **Zero Secrets**: Never commit secrets or credentials.
- **Explicit Types**: Use TypeScript interfaces for frontend state and Pydantic models for backend payloads.
- **Modular Layout**: Follow the separation of concerns between `providers`, `discovery`, `collectors`, `rules`, and `engine`.
