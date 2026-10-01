# AI-Assisted Context-Aware Cybersecurity Remediation Prioritization

## Project Overview

This project is a cybersecurity analytics and decision-support system that models an organization's security environment as a graph, discovers realistic multi-hop attack paths, evaluates contextual risk, identifies high-impact vulnerabilities and bottlenecks, evaluates remediation actions through deterministic what-if simulation, selects optimal remediation sets under budget, and explains results through a grounded AI explanation layer.

## Central Research Question

> **When remediation resources are limited, how can we prioritize security remediation using attack-path context and environmental/business context rather than relying only on isolated vulnerability severity?**

## Major Capabilities

- **Canonical Security Graph**: Directed `MultiDiGraph` of assets, vulnerabilities, findings, and attack transitions.
- **Attack Path Discovery**: Multi-hop entry-point → crown-jewel pathfinding (`all` / `shortest` / `cheapest` modes).
- **Contextual Prioritization**: Policy-independent `PriorityProfile` evidence plus configurable `OperationalOrdering` (no universal score by design).
- **Blast Radius Analysis**: Bounded Pareto-based downstream reachability from a compromised asset.
- **Chokepoint Analysis**: Bottleneck entities ranked by normalized chokepoint score and RWPC.
- **What-If Remediation Simulation**: Deterministic sequential simulation on an immutable baseline copy, with before/after deltas and rank comparison.
- **Budget Optimization**: Exact simulation-evaluated subset enumeration under a hard budget (O1/O2 lexicographic objective, 12-action ceiling).
- **Interactive Visualization**: React + Cytoscape.js dashboard (graph, paths, blast radius, chokepoints, simulation, optimization).
- **Explainable AI**: Structured finding/simulation/optimization explanations with mandatory AVAILABLE / FALLBACK / UNAVAILABLE provider-status display and deterministic fallback (no key required).

## Architecture Overview

```text
Browser → http://localhost:8080
  └─ Frontend container (nginx: React SPA + /api reverse proxy)
       └─ Backend container (FastAPI/Uvicorn :8000, SQLite on a persistent volume)
```

The backend is authoritative for all security calculations; the frontend only visualizes backend results.

## Technology Stack

- **Backend**: Python 3.13, FastAPI, Pydantic v2, SQLAlchemy 2.0, SQLite, Alembic, NetworkX, Uvicorn
- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, React Router v7, Cytoscape.js, nginx (production)
- **AI provider (optional)**: Groq SDK with strict structured outputs; deterministic fallback with no key
- **Testing**: Pytest (backend), `tsc` + `oxlint` + `vite build` (frontend)

## Repository Structure

```text
.
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI entrypoint — ALL routes live here
│   │   ├── analysis/             # path, blast radius, chokepoint, prioritization,
│   │   │                         # simulation, optimization, explanation (deterministic side)
│   │   ├── core/                 # settings (.env), database session
│   │   ├── graph/                # canonical graph builder, edge semantics, validators
│   │   ├── models/               # SQLAlchemy domain models
│   │   ├── schemas/              # Pydantic request/response contracts
│   │   └── services/             # explanation provider abstraction + Groq adapter
│   ├── data/seeds/seed_data.py   # deterministic demo scenario (+ remediation actions)
│   ├── tests/                    # backend test suite
│   └── Dockerfile                # production backend image
├── frontend/
│   ├── src/
│   │   ├── features/             # dashboard, scenario, assets, findings, prioritization,
│   │   │                         # graph, attack-paths, blast-radius, chokepoints,
│   │   │                         # remediation, optimization, explanation
│   │   ├── services/api.ts       # centralized typed API client
│   │   ├── types/api.ts          # TypeScript mirrors of backend schemas
│   │   └── context/              # scenario selection state
│   ├── nginx.conf                # SPA fallback + /api proxy (production)
│   └── Dockerfile                # multi-stage build → nginx
├── docker-compose.yml            # full-stack orchestration
├── requirements.txt              # backend dependencies
├── .env.example                  # safe placeholders (no secrets)
└── README.md
```

---

# OPTION 1 — DOCKER (recommended / easiest)

## Prerequisites

- Docker Desktop (daemon running) with Docker Compose v2
- Git
- No API key required (deterministic fallback is the default)

## Commands

```bash
git clone <repository-url>
cd Capstone_project-2-1

# Optional: copy .env.example to .env only if you need custom settings.
# The stack works WITHOUT any .env file (AI_PROVIDER defaults to none).
docker compose up --build
```

Open the application: **http://localhost:8080**

```bash
# Follow logs
docker compose logs -f

# Stop (database persists in the db-data volume)
docker compose down

# Rebuild after code changes
docker compose up --build

# Full reset (deletes the SQLite volume; demo data reseeds on next start)
docker compose down -v
```

## What runs

| Service  | Image build              | Purpose                              |
|----------|--------------------------|--------------------------------------|
| backend  | `backend/Dockerfile`     | FastAPI on internal port 8000        |
| frontend | `frontend/Dockerfile`    | nginx on host port 8080, proxies `/api` to `backend:8000` |

## Database persistence

SQLite lives at `/data/cybersecurity.db` inside the backend container, backed by the named volume `db-data`. Container restarts and `docker compose down` preserve it; only `docker compose down -v` deletes it.

## Demo data initialization

On every backend start, tables are created if missing and the deterministic demo scenario (`basic_test_scenario`: 3 assets, 2 findings, 5 edges, 4 remediation actions) is seeded idempotently — restarting never duplicates rows.

## Groq configuration (optional)

AI explanation works out of the box via deterministic fallback (`AI_PROVIDER=none` default in Compose). To enable live AI output, create a local `.env` file (gitignored, never baked into images):

```ini
AI_PROVIDER=groq
GROQ_API_KEY=your_actual_key_here
```

Compose reads `.env` for variable interpolation only. The key never reaches the browser; the frontend only calls the backend `/explain` endpoint.

### Provider status meanings

- `AVAILABLE` — AI-generated explanation (validated against backend evidence)
- `FALLBACK` — deterministic template; NOT AI-generated (shown when no usable provider output exists)
- `UNAVAILABLE` — provider failed and no content could be produced

---

# OPTION 2 — MANUAL DEVELOPMENT SETUP

## Prerequisites

- Python 3.13+
- Node.js 18+ and npm
- Git

## Backend setup

Run from the **repository root** (imports are `backend.app...`):

```bash
pip install -r requirements.txt
```

## Database setup / seed

Tables auto-create on backend startup. Load the deterministic demo scenario once:

```bash
python -c "from backend.data.seeds.seed_data import create_seed_data; create_seed_data()"
```

The seed is idempotent — safe to re-run. (Alembic migrations exist under `backend/alembic/` but are not required for a fresh setup.)

## Start backend

```bash
python -m uvicorn backend.app.main:app --reload --port 8000
```

- API base: `http://localhost:8000/api`
- Health: `http://localhost:8000/api/health`
- Interactive docs: `http://localhost:8000/docs`

## Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Open: **http://localhost:5173** (Vite proxies `/api` to `http://localhost:8000`).

## Configure `.env` (optional)

```bash
cp .env.example .env
```

Leave `GROQ_API_KEY` blank for deterministic fallback, or add a key to enable live AI output. `.env` is gitignored — never commit it.

---

# TESTING

## Backend

From the repository root:

```bash
pytest -q
```

Expected baseline: **239 passed**.

## Frontend

From `frontend/`:

```bash
npm run build    # tsc typecheck + production build
npm run lint     # oxlint
```

Both must pass with no errors (warnings only).

---

# TROUBLESHOOTING

- **Port already in use** (`8080` or `8000`/`5173`): stop the conflicting process, or change the published port in `docker-compose.yml` (`"8081:80"`).
- **Docker daemon not running**: start Docker Desktop and wait until `docker info` succeeds before `docker compose up`.
- **Frontend shows blank / API errors**: confirm the backend is healthy (`docker compose ps` shows `backend` as `healthy`; `GET /api/health` returns 200).
- **Empty scenario data in Docker**: check `docker compose logs backend` for the seed message; if the volume holds a stale pre-seed database, reset with `docker compose down -v` and start again.
- **`/assets` page not loading in production**: fixed via nginx `try_files` without directory matching (Vite's `/assets/` bundle dir collides with the SPA route).
- **Explanation shows FALLBACK**: expected without a Groq key — deterministic output, not an error. With a key, rate limits surface as UNAVAILABLE; retry later.
- **Windows PowerShell**: `&&` chaining is not supported in Windows PowerShell 5.1 — run commands separately or join with `;`.
- **Tests fail with `ModuleNotFoundError: No module named 'backend'`**: run pytest from the repository root, not from `backend/`.

---

# CAPSTONE DEMO FLOW

Recommended systematic walkthrough (single scenario selected throughout):

1. **Scenario** — confirm details and entity counts (3 assets, 2 findings, 5 edges, 4 actions).
2. **Assets / Findings** — browse tables, filters, and finding→explanation deep links.
3. **Prioritization** — backend ordering, policy panel, per-finding evidence ("Why here?").
4. **Security Graph** — node/edge selection, zoom/fit/reset, legend.
5. **Attack Paths** — `all` / `shortest` / `cheapest` modes, path selection with graph highlighting.
6. **Blast Radius** — pick `asset-web-01`, compute, inspect affected assets and crown-jewel reach.
7. **Chokepoints** — ranked entities, select to highlight the node.
8. **Remediation Simulation** — select `rem-patch-finding-01` + `rem-remove-direct-db-path`, run (2 → 0 paths), inspect deltas and remediated findings.
9. **Budget Optimization** — candidates with budget `10.0` (selects 2 actions, cost 8.0), then budget `0` (empty selection with reason).
10. **AI Explanation** — finding/simulation/optimization tabs; observe FALLBACK status without a key and evidence references on every claim.

## License

This project is for educational purposes as a capstone project.
