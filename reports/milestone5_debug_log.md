# Milestone 5 — Debugging record

## DEF-01: Unauthorized source accepted as remediation
- **Original behavior:** VM1 SSH accepted `10.1.1.0/24` as a remediation because it narrowed the original `0.0.0.0/0` rule.
- **Cause:** `simulate_firewall_remediation()` checked CIDR containment but not whether the resulting source was authorized by the SSH service exposure policy.
- **Correction:** Reassess the copied VM after modification and reject the proposal if `policy_compliant` is not `True` or `review_required` is `True`.
- **Retest:** Proposed management CIDR `10.0.4.0/24` is accepted and yields Low (score 0); unauthorized `10.1.1.0/24` is rejected; original VM is unchanged.
- **Status:** Fixed and retested.

## DEF-02: Invalid TCP timeout not consistently validated
- **Original behavior:** Unsupported timeouts such as `None`, strings, and `NaN` could cause an inconsistent exception inside the scanner/socket path.
- **Cause:** Comparison-based validation lacked type and finite-value checks.
- **Correction:** Validate timeout type and numerical finiteness first, returning `ValueError` for all invalid inputs.
- **Retest:** Invalid timeouts `0`, `-1`, `6`, `NaN`, `invalid`, and `None` are all rejected.
- **Status:** Fixed and retested.

## Verification scope
- 52 scenario checks passed and 12 unittest methods passed in this environment.
- Real TCP connectivity was checked exclusively on the local loopback interface, with a temporary listening socket.
- Automated UI browser interaction was **not executed** because Streamlit is not installed in this runtime. Manual browser verification remains required.
- No actual cloud resources, public IP hosts, security groups or network firewalls were scanned or altered.
