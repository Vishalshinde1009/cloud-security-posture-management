# Cloud Security Posture Management (CSPM) Platform

> **Final-Year Academic Cybersecurity Project**  
> *Cloud Security Posture Management Dashboard for Automated Cloud Misconfiguration Detection and Risk Assessment*

[![Security: Read-Only](https://img.shields.io/badge/Security-Strict%20Read--Only-blue.svg)](#security-principles)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-green.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18%2B-cyan.svg)](https://reactjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Project Overview
The **Cloud Security Posture Management (CSPM)** platform is an enterprise-grade cybersecurity system designed to audit cloud environments for dangerous security misconfigurations, calculate deterministic and explainable risk scores, map findings to industry benchmarks (such as CIS AWS Foundations Benchmark), and present actionable remediation guidance to Security Operations Center (SOC) analysts.

### Key Capabilities
- **Strict Read-Only Inspection**: Zero modifying actions on cloud infrastructure. Scanner exclusively calls `Describe*`, `Get*`, and `List*` APIs.
- **Dual Execution Engine**:
  - `CSPM_MODE=mock`: Realistic deterministic offline testbed for safe demonstration and automated testing without AWS costs or credentials.
  - `CSPM_MODE=aws`: Real-time AWS scanning via Boto3 with least-privilege IAM policies.
- **Supported AWS Services**: S3, IAM, EC2, VPC / Security Groups, CloudTrail, RDS.
- **Rule Engine**: Modular rule execution isolating rule evaluation errors to guarantee scan completion.
- **Mathematical Risk Scoring**: Explainable 0–100 risk scoring factoring severity, internet exposure, data sensitivity, and asset criticality.
- **Multi-Scan Drift Tracking**: Historical comparison between consecutive scans detecting *New*, *Resolved*, and *Persistent* findings.
- **Executive & Technical PDF Reports**: Automated downloadable reports summarizing posture scores, compliance matrix, and remediation plans.

---

## 2. System Architecture

```text
+-----------------------+        +-----------------------+
|   AWS Infrastructure  |        |    Mock Environment   |
|   (Boto3 Read-Only)   |        |   (Deterministic Data)|
+-----------+-----------+        +-----------+-----------+
            \                                /
             \                              /
              v                            v
        +----------------------------------------+
        |        Cloud Provider Adapter          |
        |      (Resource Discovery Engine)       |
        +-------------------+--------------------+
                            |
                            v
        +----------------------------------------+
        |    Configuration Collection Service    |
        |   (S3, IAM, EC2, VPC, CloudTrail, RDS) |
        +-------------------+--------------------+
                            |
                            v
        +----------------------------------------+
        |         Security Rule Engine           |
        |    (Rule Registry, Isolated Runner)    |
        +-------------------+--------------------+
                            |
                            v
        +----------------------------------------+
        |        Explainable Risk Engine         |
        |  (Risk = Severity * Exposure * Asset)  |
        |  (Overall Posture: 0 - 100 Score)      |
        +-------------------+--------------------+
                            |
            +---------------+---------------+
            |                               |
            v                               v
+-----------------------+       +-----------------------+
|  FastAPI REST API     |       |  PDF Report Generator |
|  & Background Workers |       |    (Executive / Tech) |
+-----------+-----------+       +-----------------------+
            |
            v
+-----------------------+
| React SOC Dashboard   |
| (Vite, TS, Tailwind)  |
+-----------------------+
```

---

## 3. Directory Layout

```text
project-ESE/
├── .env.example               # Environment variable template with documentation
├── .gitignore                  # Git ignore preventing secret and artifact leaks
├── docker-compose.yml          # Container orchestration (Postgres, Backend, Frontend)
├── README.md                   # System documentation and setup guide
├── docs/                       # Architectural and technical documentation
│   ├── architecture.md         # Detailed pipeline and component design
│   └── aws-setup.md            # Read-only IAM policy and AWS onboarding guide
├── backend/                    # FastAPI Python Backend
│   ├── app/
│   │   ├── main.py             # FastAPI entrypoint, middleware, security headers
│   │   ├── core/               # Configuration, security, logging
│   │   │   ├── config.py       # Pydantic Settings
│   │   │   ├── logging.py      # Structured SOC logging
│   │   │   └── security.py     # Password hashing & JWT auth
│   │   ├── database/           # SQLAlchemy session and models
│   │   ├── api/                # REST API routers
│   │   │   └── health.py       # Healthcheck endpoint
│   │   ├── models/             # ORM database entities
│   │   ├── schemas/            # Pydantic validation schemas
│   │   ├── services/           # Business logic services
│   │   └── scanner/            # CSPM Discovery, Collection, and Rule Engine
│   │       ├── providers/      # AWS and Mock provider adapters
│   │       ├── discovery/      # Resource discovery
│   │       ├── collectors/     # Per-service metadata collectors
│   │       ├── rules/          # 20+ security rule implementations
│   │       └── engine/         # Rule evaluation pipeline
│   ├── tests/                  # Pytest test suite
│   ├── requirements.txt        # Python dependencies
│   └── Dockerfile              # Backend container definition
└── frontend/                   # React + TypeScript + Vite + Tailwind Frontend
    ├── src/
    │   ├── App.tsx             # Main dashboard UI
    │   ├── main.tsx            # React DOM mounting
    │   └── index.css           # Tailwind styles and custom dark theme
    ├── public/                 # Static assets & favicon
    ├── package.json            # Node dependencies
    ├── vite.config.ts          # Vite build config & proxy
    ├── tailwind.config.js      # Tailwind configuration with cyber color scheme
    └── Dockerfile              # Frontend container definition
```

---

## 4. Quickstart Guide

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Docker and Docker Compose (optional, for full containerized deployment)

### 4.1 Running with Docker Compose
```bash
# 1. Copy environment template
cp .env.example .env

# 2. Build and start services
docker-compose up --build
```
- Frontend: `http://localhost:3000`
- Backend API Docs: `http://localhost:8000/api/docs`

### 4.2 Running Locally (Development Mode)

#### Backend Setup:
```bash
# Navigate to backend
cd backend

# Create and activate virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --reload --port 8000
```

#### Frontend Setup:
```bash
# Navigate to frontend
cd frontend

# Install packages
npm install

# Start Vite development server
npm run dev
```
Visit `http://localhost:5173` to access the application.

---

## 5. Security & Academic Integrity
1. **No Hardcoded Secrets**: All keys, passwords, and tokens are read exclusively from environment variables or IAM roles.
2. **Auditability**: All actions are logged with timestamp, user identity, action, and target resource.
3. **Transparent Scoring**: Risk scores are calculated using clear mathematical formulas rather than arbitrary numbers.
