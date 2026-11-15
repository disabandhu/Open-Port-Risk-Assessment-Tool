# Streamlit browser acceptance checklist — run on your laptop

Command: `python -m streamlit run ui/app.py`

Record date, environment, actual result and a screenshot for each case.

| ID | Page | Procedure | Expected | Actual / Evidence |
|---|---|---|---|---|
| UI-01 | Dashboard | Open URL | 15 VMs, 27 ports, 6 High, 3 Medium, 18 Low | Not run here |
| UI-02 | Dashboard | Inspect chart and priority findings | Distribution equals engine report; VM comparisons present | Not run here |
| UI-03 | VM Explorer | Select VM1 | 3 ports, SSH 22 High with firewall source `0.0.0.0/0` | Not run here |
| UI-04 | VM Explorer | Select VM15 | No configured ports message, no exception | Not run here |
| UI-05 | Risk Findings | Filter Medium | Only Medium findings shown | Not run here |
| UI-06 | Risk Findings | Search `PostgreSQL` | Database findings shown | Not run here |
| UI-07 | Remediation | VM1 / 22 / `10.0.4.0/24` | High score 8 → Low score 0 | Not run here |
| UI-08 | Remediation | VM1 / 22 / `10.1.1.0/24` | Error: subnet violates service access policy | Not run here |
| UI-09 | Remediation | Reset comparison | Comparison cleared; original VM1 still broad SSH | Not run here |
| UI-10 | Reports | Export CSV | 27 rows; VM/port/risk present | Not run here |
| UI-11 | Reports | Export PDF | Opens successfully; findings and limitations visible | Not run here |
| UI-12 | Responsive | Narrow browser window | No clipped critical controls; usable navigation | Not run here |

Mark actual observations truthfully after browser testing; do not replace expected results with assumed PASS values.
