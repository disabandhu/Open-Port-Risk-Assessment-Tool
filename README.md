# Python-Based Open Port Risk Assessment Tool

<video src="https://raw.githubusercontent.com/disabandhu/Open-Port-Risk-Assessment-Tool/main/assets/demo.mp4" autoplay loop muted playsinline style="width: 100%;"></video>

Refactored Phase E project. Runs on Python **3.10+** without Colab.

## 🚀 Quick Start — How to Run the Dashboard Locally

Follow these steps to run the **Open Port Risk Assessment Dashboard** on your computer. No prior experience is required!

### Step 1: Get the Project on Your Computer

1. Install Git from [git-scm.com/downloads](https://git-scm.com/downloads) if it is not already installed.
2. Open Command Prompt or Terminal and run:

```bash
git clone https://github.com/disabandhu/Open-Port-Risk-Assessment-Tool.git
cd Open-Port-Risk-Assessment-Tool
```

This downloads the repository to your computer and opens the project folder. Continue with Step 2 to install Python.

### Step 2: Install Python (If Not Already Installed)

1. Download Python from [python.org/downloads](https://www.python.org/downloads/).
2. Install **Python 3.10 or newer**.
3. **Windows users:** During installation, enable **"Add Python to PATH"** if the installer offers this option.
4. Open Command Prompt or Terminal and enter:

```bash
python --version
```

If a Python version appears (for example, `Python 3.11.9`), you're ready!

### Step 3: Open the Project Folder in a Terminal

**For Windows users:**

1. Open the downloaded `open_port_risk_assessment` folder.
2. Click the address bar at the top of File Explorer.
3. Type `cmd` and press **Enter**.
4. A Command Prompt window will open directly inside your project folder.

**For macOS/Linux users:**

Open Terminal and navigate to the extracted project folder using the `cd` command.

**Important:** Make sure you're inside the folder containing `requirements.txt`. You do not need to run `cd open_port_risk_assessment` if you opened the terminal directly inside that folder.

### Step 4: Create a Virtual Environment (Optional but Recommended)

In the terminal, enter:

```bash
python -m venv .venv
```

This creates an isolated environment for the project.

**Windows (Command Prompt):**

```bat
.venv\Scripts\activate.bat
```

**Windows (PowerShell):**

```powershell
.venv\Scripts\Activate.ps1
```

**macOS/Linux:**

```bash
source .venv/bin/activate
```

Once activated, you should see `(.venv)` at the beginning of your terminal line.

### Step 5: Install Required Libraries

Copy and paste this command into the terminal:

```bash
python -m pip install -r requirements.txt
```

Press **Enter** and wait until installation finishes. This may take a few minutes.

You only need to install these dependencies once per virtual environment.

### Step 6: Start the Dashboard

Run the following command:

```bash
python -m streamlit run ui/app.py
```

Press **Enter**.

Streamlit will start the application and should automatically open the dashboard in your default web browser.

### Step 7: Open the Dashboard

If your browser doesn't open automatically:

1. Look at the terminal window.
2. Find the **Local URL**, usually:

   `http://localhost:8501`

   If it doesn't work try the **Network URL**

3. Copy the URL and paste it into your browser.

**Congratulations! 🎉 Your Open Port Risk Assessment Dashboard should now be running.**

### Step 8: Explore the Dashboard

Use the sidebar to navigate between different sections:

| Tab | What It Does |
|---|---|
| **Dashboard** | Provides an overview of the port risk assessment results. |
| **VM Explorer** | Lets you explore virtual machines and their detected open ports. |
| **Risk Findings** | Displays identified security risks and their severity levels. |
| **Remediation** | Provides recommendations for addressing identified risks. |
| **Reports** | Lets you view assessment reports and available reporting options. |

### Step 9: Stop the Application

When you're finished:

1. Return to the terminal where Streamlit is running.
2. Press **Ctrl + C**.
3. The application will stop.

---

### ⚠️ Common Problems and Solutions

**Problem: `python` is not recognized**

Python may not be installed or added to your system PATH. Install Python and restart your terminal. On Windows, you can also try `py` instead of `python`.

**Problem: `No module named streamlit`**

Make sure your virtual environment is activated, then run:

```bash
python -m pip install -r requirements.txt
```

**Problem: `File does not exist: ui/app.py`**

You are probably in the wrong directory. Make sure your terminal is inside the `open_port_risk_assessment` folder containing `requirements.txt` and the `ui` folder.

**Problem: The dashboard doesn't open automatically**

Copy the **Local URL** displayed in the terminal and open it manually in your browser.

**Problem: Port 8501 is already in use**

Run the dashboard using a different port:

```bash
python -m streamlit run ui/app.py --server.port 8502
```

Then open `http://localhost:8502` in your browser.

---

**Note:** Keep the terminal window open while using the dashboard. Closing it will stop the application.

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
