# AI-Assisted Context-Aware Cybersecurity Remediation Prioritization

## Project Overview

This project is a cybersecurity analytics and decision-support system that models an organization's security environment as a graph, discovers realistic multi-hop attack paths, evaluates contextual risk, identifies high-impact vulnerabilities and bottlenecks, and evaluates remediation actions through deterministic what-if simulation.

## Central Research Question

> **When remediation resources are limited, how can we prioritize security remediation using attack-path context and environmental/business context rather than relying only on isolated vulnerability severity?**

## Key Features

- **Canonical Security Graph**: Directed graph model of assets, vulnerabilities, and attack transitions (MultiDiGraph) - implemented
- **Attack Path Discovery**: Multi-hop pathfinding from entry points to crown jewels - planned
- **Contextual Risk Scoring**: Multi-factor risk model incorporating CVSS, exploitability, exposure, asset criticality, path participation, crown jewel impact, and blast radius
- **Contribution/Bottleneck Analysis**: Identifies critical vulnerabilities and choke points in attack paths - planned
- **Blast Radius Analysis**: Quantifies downstream impact of asset compromise
- **What-If Remediation Simulation**: Deterministic simulation of remediation effects on immutable baseline graph
- **Resource-Constrained Optimization**: Budget-aware remediation selection using knapsack/greedy algorithms
- **Interactive Visualization**: React frontend with Cytoscape.js graph visualization - planned
- **Explainable AI**: Structured explanations for all risk scores and remediation impacts - planned

## Technology Stack

- **Backend**: Python 3.13+, FastAPI, Pydantic v2, SQLAlchemy 2.0, SQLite, Alembic
- **Graph Engine**: NetworkX 3.4+ (deterministic, in-memory, MultiDiGraph)
- **Frontend**: React 18/19, TypeScript, Vite, Cytoscape.js, Tailwind CSS
- **Testing**: Pytest (backend), Jest/Vitest (frontend planned)

## Getting Started

### Prerequisites

- Python 3.13+
- Node.js 18+ and npm
- Git

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
python -m uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

## Project Structure

See [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) for detailed directory structure and module responsibilities.

## Documentation

- [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) - Project identity and objectives
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture and data flow
- [DATA_MODEL.md](DATA_MODEL.md) - Domain entity specifications
- [API_CONTRACT.md](API_CONTRACT.md) - REST API endpoint definitions
- [DECISIONS.md](DECISIONS.md) - Architectural and research decisions
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) - Current progress tracking
- [TODO.md](TODO.md) - Ordered backlog of tasks
- [CHANGELOG.md](CHANGELOG.md) - Development history
- [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) - Chronological engineering journal
- [AI_HANDOFF.md](AI_HANDOFF.md) - Handoff protocol for AI agents
- [RESEARCH_NOTES.md](RESEARCH_NOTES.md) - Reference repository analysis

## License

This project is for educational purposes as a capstone project. See individual reference repositories for their respective licenses.

## Acknowledgments

This project references and adapts concepts from:
- AttackGraph v2 (Abd-Rahman-Cyber/AttackGraph)
- LateralScope (jithinmathws/lateralscope)
- Neo4j Cyber VPEM (neo4j-field/cyber-vpem)
- Neo4j Cyber APA (neo4j-field/cyber-apa)
- Graph-Based Attack Path Modeler (nicky-quist/attack-path-modeler)
- Cyber Attack Path Simulation (shrikarak/cyber-attack-path-simulation)

*Note: Concepts are adapted, not copied. All implementations are original work using the specified technology stack.*