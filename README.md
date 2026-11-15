# Python-Based Open Port Risk Assessment Tool

Refactored Phase E project. Runs on Python **3.10+** without Colab.

## Quick start — RUN the dashboard locally

**Prerequisite:** Python **3.10+** installed (with `pip`). Open a terminal in the **repository root**, where `requirements.txt` is located.

```bash
# Optional but recommended: create an isolated environment
python -m venv .venv

# Activate it on Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On macOS/Linux instead: source .venv/bin/activate

# Install dependencies and start the dashboard
python -m pip install -r requirements.txt
python -m streamlit run ui/app.py
```

If the Streamlit launch upon running the command - python -m streamlit run ui/app.py, does not open the page then open the **Network URL** printed by Streamlit in your terminal in your browser. Use the sidebar to explore **Dashboard**, **VM Explorer**, **Risk Findings**, **Remediation**, and **Reports**. To stop the server, press **Ctrl+C** in the terminal.

> **Windows Command Prompt:** use `.venv\Scripts\activate.bat` instead of the PowerShell activation command. If `python` is not recognized on Windows, try `py -3` in its place. The assessment uses **simulated** VM/firewall data; no live cloud accounts or scans are required.

For a guided demonstration, expected outputs, troubleshooting, CLI options, and an explanation of every tab, see **[PROJECT_WALKTHROUGH.md](PROJECT_WALKTHROUGH.md)**.

### Command-line assessment (optional)

```bash
python main.py            # Print the assessment in the terminal
python main.py --export   # Also write reports/assessment.json and reports/findings.csv
python -m unittest discover -s tests -v  # Run regression tests
```

## Layout

- `core/models.py`: dataclass equivalents of the notebook VM and NetworkConfig objects
- `simulation/environment.py`: deterministic Phase B 15-VM/27-port scenario configuration
- `core/discovery.py`: discovery from **simulated configuration**, not live scanning
- `core/firewall.py`, `core/policies.py`, `core/risk_engine.py`: Phase C policy and scoring
- `core/recommendations.py`, `core/assessment.py`: individual/integrated assessment
- `core/scanner.py`: separate loopback-only TCP connect scanner
- `core/remediation.py`: copy-based, non-destructive simulated firewall remediation
- `tests/`: built-in unittest regression/scenario tests
- `ui/`: Phase F Streamlit dashboard and dark-theme styles
- `data/dataset.xlsx`, `notebooks/`: original scheduling dataset and historical notebook

## Scope

Addresses in `203.0.113.0/24` are documentation addresses. Simulated firewall source rules are not enforced by live systems. Scores are project heuristics, **not CVSS** or a vulnerability scan. The original A2C training notebook is archived separately; **the standalone risk engine does not run or reproduce the A2C scheduler**. Host assignments remain metadata and are not capacity-checked.

The included tests verify the recreated Phase B/C design. They do **not** prove parity with a later Colab notebook that was not provided. To verify exact parity, export the latest notebook findings into a normalized JSON and compare by `(vm, port)` including fields and values.

## Phase F — Streamlit dashboard

Install and launch from the repository root (Python 3.10+):

```bash
python -m pip install -r requirements.txt
python -m streamlit run ui/app.py
```

The app provides **Dashboard**, **VM Explorer**, **Risk Findings**, **Remediation**, and **Reports** views. All data is produced by the existing `simulation.environment.load_environment()` and `core.assessment.run_security_assessment()` functions.

- **Remediation** assesses only a deep copy of a VM; the original configuration and downloadable baseline reports are unchanged.
- **CSV/PDF** reports contain current computed findings, not hardcoded sample values.
- No accounts, database, live cloud provider connection, or remote scanning are implemented.
- UI is intended for local demonstration. The separate localhost-only scanner remains available from `core/scanner.py`.
- The numeric score is a project heuristic, not CVSS.

To run the automated tests:

```bash
python -m unittest discover -s tests -v
```

## Milestone 5: Testing and security validation

Run the full unit/integration suite:

```bash
python -m unittest discover -s tests -v
```

Generate a true expected-versus-actual test matrix from executable test scenarios:

```bash
python validate_milestone5.py
```

Outputs: `reports/milestone5_test_matrix.csv` and `reports/milestone5_summary.json`.

See `reports/milestone5_debug_log.md` for defects fixed and `tests/UI_MANUAL_CHECKLIST.md` for browser checks that must be carried out in Streamlit locally.
