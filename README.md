# AEGIS

**Adaptive Ensemble for Grid Intrusion Shielding** is a research prototype for cyber-physical security operations in industrial control systems (ICS). It brings attack simulation, machine-learning detection, physics-informed safety checks, and operator review into one Streamlit dashboard.

> AEGIS is a demonstration and research system. It is not a certified protection system and should not be connected to operational infrastructure or used to make production control decisions.

## What it does

- Simulates benign telemetry and selected attack scenarios mapped to MITRE ATT&CK techniques.
- Scores telemetry with a heterogeneous Random Forest, Extra Trees, XGBoost, and CatBoost ensemble.
- Tracks disagreement between models and evaluates candidate mitigations in a digital-twin workflow.
- Checks grid signals and proposed mitigations in a physics-informed simulator, including voltage, current, power, frequency, breaker, line, and transformer indicators.
- Presents an operator approval flow and writes compliance-oriented event records.
- Includes an ablation study interface and a conditional diffusion-based zero-day experiment.

The app has three sections: **Live SOC Operations**, **Research Experiments & Ablation Study**, and **GenAI Zero-Day Lab**.

## Architecture

```text
Simulated telemetry ──> ML ensemble ──> uncertainty and risk assessment
        │                                      │
        └──────────────────────────────────────┤
                                               v
                               mitigation + digital-twin sandbox
                                               │
                                               v
                                   physics safety evaluation
                                               │
                                               v
                              operator review + audit event
```

The principal components live in `src/`:

| Module | Responsibility |
| --- | --- |
| `red_team.py` | Vulnerability and attack scenario simulation |
| `blue_team.py` | Four-model threat scoring ensemble |
| `uncertainty_engine.py` | Ensemble uncertainty evaluation |
| `mitigation_engine.py`, `digital_twin.py` | Candidate mitigation workflow and sandbox |
| `physics_twin.py` | Grid-signal checks, mitigation simulation, and risk fusion |
| `compliance_logger.py` | Compliance-oriented event logging |
| `ablation_study.py` | Architecture tier benchmarking |
| `zero_day_generator.py` | Conditional diffusion experiment |

## Requirements

- Python 3.10 or newer
- The Python packages listed in `requirements.txt`
- PyTorch, required by `src/zero_day_generator.py` (not currently listed in `requirements.txt`)

## Quick start

```bash
git clone <repository-url>
cd resilshield_ai

python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install torch
streamlit run app.py
```

Streamlit prints a local URL (usually `http://localhost:8501`) when the dashboard starts. Choose a PyTorch installation appropriate for your operating system and hardware if the default `pip install torch` is unsuitable.

The repository includes trained model artifacts under `src/saved_models/`. If the app cannot load the artifacts, the ensemble implementation can train from `data/synthetic_logs.csv`. The BATADAL training utility expects the source CSV at the repository root as `t.csv`; run it with:

```bash
python data/train_batadal.py
```

The training script may overwrite model artifacts. Keep a copy of the existing files if you need to preserve them.

## Configuration and data

- `config/settings.py` defines feature columns, decision thresholds, attack scenarios, compliance mappings, and the active dataset mode (`batadal` by default).
- `data/synthetic_logs.csv` contains synthetic telemetry used by the fallback training flow.
- `t.csv` is the BATADAL dataset used by `data/train_batadal.py`.
- `src/saved_models/` contains serialized model and scaler artifacts. Only load joblib artifacts from sources you trust.
- `logs/` is used for compliance audit output when the app records events.

No external API key is configured by the application. Scenarios and telemetry are simulated locally; the project does not provide a live SCADA connector.

## Project layout

```text
.
├── app.py                         # Streamlit dashboard
├── config/settings.py             # Dataset, scenario, and threshold settings
├── data/
│   ├── generate_logs.py           # Synthetic telemetry generation
│   ├── synthetic_logs.csv         # Synthetic training data
│   └── train_batadal.py            # BATADAL feature/training pipeline
├── src/                            # Detection, simulation, and audit modules
│   └── saved_models/              # Pre-trained model artifacts
├── requirements.txt
└── HACKATHON_SUBMISSION_REPORT.md # Extended project and evaluation report
```

## Screenshots

Selected dashboard views:

| Live threat detection | Operator review and compliance |
| --- | --- |
| ![SOC live threat detection](ss1_soc_live_threat_detection.png) | ![Human-in-the-loop compliance](ss2_human_in_the_loop_compliance.png) |

Additional screenshots are available in the repository root as `ss3_...png` through `ss8_...png`.

## Evaluation notes

The project report documents a BATADAL-based training and evaluation workflow, ablation results, and example scenarios. Those results describe this prototype's datasets and experiments; they should not be interpreted as independent certification or a guarantee of detection performance on other systems. See [HACKATHON_SUBMISSION_REPORT.md](HACKATHON_SUBMISSION_REPORT.md) for the detailed methodology and demonstrations.

## License

No license file is currently included. Contact the repository owner for permission before redistributing or using this project beyond the rights granted by the repository host.
