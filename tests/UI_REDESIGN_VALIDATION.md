# PortShield UI redesign — validation record

## Automated checks executed

- `python -m compileall -q ui`: passed (syntax).
- `python -m pytest -q`: 12 tests passed; 60 subtests passed.
- `python validate_milestone5.py`: 52 checks passed, 0 failed (assessment counts, policy, firewall, remediation and report generation).
- Source inspection: five existing views preserved; no Localhost Scanner tab added; no core engine or simulated environment changes.

## Browser checks still required

Streamlit is not installed in the execution environment. Attempting to install it failed because package index/DNS access was unavailable. **The app was not launched in a browser**, and the UI actions below have not been interactively verified.

Run `python -m pip install -r requirements.txt` and `python -m streamlit run ui/app.py` on a machine with the dependencies available.

1. Dashboard: check the two-tier metrics, bar charts, priority table, and priority-finding details.
2. VM Explorer: select VM1 and VM15, inspect long values, rules and the empty-port case.
3. Risk Findings: filter Medium, search PostgreSQL and long recommendations, inspect the selected finding.
4. Remediation: test VM1 port 22 with `10.0.4.0/24` (expected risk 8 → 0), invalid `10.1.1.0/24`, and Reset.
5. Reports: download CSV and PDF, open files, and inspect full exported details.
6. At browser widths 1440, 1024 and 768 pixels, verify labels, selector dropdowns, text wrapping, chart legends, table scrolling and no clipping. The table uses horizontal scroll only below 720px, with full accessible cell text.
7. Temporarily test unusually long VM names, services and recommendation values in a **test-only copy** of the session data, without editing the committed simulation environment.

## Intentional design decisions

- Findings summaries show six essential fields in full-wrapping HTML tables. Complete exposure, policy details, reasoning and recommendations remain available through dedicated detail sections, rather than compressing ten fields into tiny table columns.
- Table-column sorting from the earlier `st.dataframe` presentation is replaced by severity-prioritized rows and filtering controls. The underlying data ordering and computed risk values are unchanged.
- Reports and remediation continue to use the existing backend functions; preview does not alter baseline exports.
