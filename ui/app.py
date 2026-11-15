"""PortShield Streamlit interface for the existing assessment engine.

Launch from the repository root: ``streamlit run ui/app.py``.
All security data, calculations and proposed changes come from the existing engine.
Only the presentation is defined here.
"""
import sys
from pathlib import Path
from copy import deepcopy
import ipaddress
from html import escape

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st

from simulation.environment import load_environment, NETWORK_SEGMENTS
from core.assessment import run_security_assessment
from core.firewall import evaluate_firewall
from core.remediation import simulate_firewall_remediation
from core.reporting import findings_csv, assessment_pdf

st.set_page_config(
    page_title='PortShield | Open Port Risk Assessment',
    page_icon='🛡️', layout='wide', initial_sidebar_state='expanded',
)

RISK_ORDER = ['High', 'Medium', 'Low', 'Review Required']
RISK_STYLES = {'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Review Required': 'review'}
style_path = Path(__file__).with_name('styles.css')
st.markdown(f'<style>{style_path.read_text(encoding="utf-8")}</style>', unsafe_allow_html=True)

if 'vms' not in st.session_state:
    st.session_state.vms = load_environment()
if 'remediation_preview' not in st.session_state:
    st.session_state.remediation_preview = None

vms = st.session_state.vms
vm_by_name = {vm.name: vm for vm in vms}

@st.cache_data(show_spinner=False)
def cached_csv(findings):
    return findings_csv(findings)

try:
    assessment = run_security_assessment(vms)
except Exception as exc:
    st.error('Security assessment could not be completed.')
    st.exception(exc)
    st.stop()

findings = assessment['findings']
summary = assessment['summary']
df = pd.DataFrame(findings)

st.sidebar.markdown('## 🛡️ PortShield')
st.sidebar.caption('CLOUD SECURITY / ASSESSMENT')
page = st.sidebar.radio('Workspace', ['Dashboard', 'VM Explorer', 'Risk Findings', 'Remediation', 'Reports'])
st.sidebar.divider()
st.sidebar.caption(f'{len(vms)} simulated VMs · Non-invasive configuration assessment')
st.sidebar.caption('Public IPs are illustrative. Risk scoring is heuristic, not CVSS.')


def safe(value):
    """Encode data for the HTML presentation components."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return '—'
    return escape(str(value), quote=True)


def pill(value):
    classification = RISK_STYLES.get(str(value), 'neutral')
    return f'<span class="ps-pill ps-{classification}">{safe(value)}</span>'


def section_header(title, description=None):
    st.subheader(title)
    if description:
        st.caption(description)


def page_header(eyebrow, title, description):
    st.markdown(f'<div class="ps-eyebrow">{safe(eyebrow)}</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<p class="ps-lead">{safe(description)}</p>', unsafe_allow_html=True)


def info_panel(label, value, detail=None):
    inner = f'<div class="ps-kicker">{safe(label)}</div><div class="ps-value">{safe(value)}</div>'
    if detail:
        inner += f'<p class="ps-secondary">{safe(detail)}</p>'
    st.markdown(f'<div class="ps-panel">{inner}</div>', unsafe_allow_html=True)


def html_table(rows, columns, widths=None, empty='No records match this selection.'):
    """Full-wrap, accessible HTML table; unlike dataframe, cells are not ellipsized."""
    if not rows:
        st.info(empty)
        return
    widths = widths or [1 / len(columns)] * len(columns)
    colgroup = ''.join(f'<col style="width:{w*100:.2f}%">' for w in widths)
    head = ''.join(f'<th scope="col">{safe(col)}</th>' for col in columns)
    body = ''.join('<tr>' + ''.join(f'<td>{safe(row.get(col))}</td>' for col in columns) + '</tr>' for row in rows)
    st.markdown(
        f'<div class="ps-table-wrap"><table class="ps-table"><colgroup>{colgroup}</colgroup>'
        f'<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def finding_table(items, include_role=False):
    """Readable prioritized summary; complete findings remain available in detail."""
    if not items:
        st.info('No findings match the current selection.')
        return
    heads = ['Virtual machine', 'Port / protocol', 'Service', 'Firewall / source', 'Severity', 'Score']
    widths = [.22, .14, .17, .23, .15, .09]
    head = ''.join(f'<th scope="col">{safe(x)}</th>' for x in heads)
    body = []
    for f in items:
        role = f'<div class="ps-secondary">{safe(f.get("role"))}</div>' if include_role else ''
        cells = [
            f'<span class="ps-strong">{safe(f["vm"])}</span>{role}',
            f'{safe(f["port"])}/{safe(f["protocol"])}',
            safe(f['service']),
            f'<span class="ps-strong">{safe(f["firewall_status"])}</span><div class="ps-secondary">{safe(f["firewall_source"])}</div>',
            pill(f['risk_level']),
            safe(f['risk_score']),
        ]
        body.append('<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>')
    colgroup = ''.join(f'<col style="width:{width*100:.2f}%">' for width in widths)
    st.markdown(
        f'<div class="ps-table-wrap"><table class="ps-table"><colgroup>{colgroup}</colgroup>'
        f'<thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def view_table(rows, columns=None, key=None):
    """Legacy table helper retained for UI callers; makes every value fully visible."""
    data = pd.DataFrame(rows)
    if columns:
        data = data.reindex(columns=columns)
    html_table(data.to_dict('records'), list(data.columns))


def risk_summary():
    """Two responsive rows rather than six cramped desktop columns."""
    first = st.columns(2, gap='medium')
    first[0].metric('Virtual machines', summary['vms'])
    first[1].metric('Configured ports', summary['configured_ports'])
    severity = st.columns(4, gap='small')
    for col, level in zip(severity, RISK_ORDER):
        col.metric(f'{level} findings', summary[level])


def finding_title(f):
    return f"{f['vm']} · {f['port']}/{f['protocol']} · {f['service']} — {f['risk_level']}"


def details_grid(pairs):
    html = ''.join(f'<div class="ps-keyval"><dt>{safe(k)}</dt><dd>{safe(v)}</dd></div>' for k, v in pairs)
    st.markdown(f'<dl class="ps-panel">{html}</dl>', unsafe_allow_html=True)


def finding_detail(f):
    a, b, c = st.columns([1, 1, 1.3], gap='medium')
    a.markdown(f'<div class="ps-panel"><div class="ps-kicker">Risk level</div><div class="ps-value">{pill(f["risk_level"])}</div></div>', unsafe_allow_html=True)
    b.metric('Risk score', f['risk_score'] if f['risk_score'] is not None else 'N/A')
    c.metric('Firewall status', f['firewall_status'])
    details_grid([
        ('Virtual machine', f['vm']), ('Service', f['service']),
        ('Port / protocol', f"{f['port']}/{f['protocol']}"),
        ('Exposure', f['exposure']), ('Allowed source', f['firewall_source']),
        ('Policy compliant', f['policy_compliant']),
    ])
    if f.get('policy_violation'):
        st.warning(f"Policy issue: {f['policy_violation']}")
    reasons = f.get('reasons') or []
    if reasons:
        st.markdown('**Assessment reasoning**')
        for reason in reasons:
            st.markdown(f'- {safe(reason)}')
    st.info(f['recommendation'], icon='💡')


def finding_view_data(data):
    if data.empty:
        return data
    keep = ['vm', 'role', 'port', 'protocol', 'service', 'firewall_status',
            'firewall_source', 'risk_level', 'risk_score', 'exposure']
    return data[keep].rename(columns={
        'vm': 'VM', 'role': 'Role', 'port': 'Port', 'protocol': 'Protocol',
        'service': 'Service', 'firewall_status': 'Firewall', 'firewall_source': 'Source',
        'risk_level': 'Risk', 'risk_score': 'Score', 'exposure': 'Exposure',
    })


if page == 'Dashboard':
    page_header('Assessment / overview', 'Security overview',
                'A live view of configured network exposure and risk across the simulated cloud environment.')
    risk_summary()
    left, right = st.columns([1, 1.6], gap='large')
    with left:
        section_header('Risk distribution', 'Number of assessed findings by severity')
        counts = pd.DataFrame({'Risk level': RISK_ORDER, 'Findings': [summary[k] for k in RISK_ORDER]}).set_index('Risk level')
        st.bar_chart(counts, horizontal=True, height=315)
    with right:
        section_header('Findings by virtual machine', 'Severity across the assessed VM inventory')
        counts = (df.groupby(['vm', 'risk_level']).size().unstack(fill_value=0)
                  .reindex(index=[vm.name for vm in vms], columns=RISK_ORDER, fill_value=0))
        st.bar_chart(counts, stack=True, height=360)
    priority = df[df['risk_level'].isin(['High', 'Review Required'])]
    section_header('Priority findings', f'{len(priority)} findings that merit attention or review')
    finding_table(priority.to_dict('records'), include_role=True)
    if not priority.empty:
        with st.expander('View full priority finding descriptions and recommendations'):
            priority_items = priority.to_dict('records')
            priority_index = st.selectbox('Priority finding', range(len(priority_items)),
                                          format_func=lambda i: finding_title(priority_items[i]), key='dashboard_priority')
            finding_detail(priority_items[priority_index])
    st.caption('Scope: simulated service and firewall configuration review only. No remote network probing is performed.')

elif page == 'VM Explorer':
    page_header('Inventory / inspect', 'VM Explorer',
                'Investigate a VM’s network context, configured ports, firewall rules and assessment results.')
    chosen = st.selectbox('Select a virtual machine', [vm.name for vm in vms],
                          format_func=lambda n: f'{n} — {vm_by_name[n].role}')
    vm = vm_by_name[chosen]
    network = vm.network
    with st.container():
        a, b = st.columns(2, gap='medium')
        with a:
            info_panel('VM role', vm.role)
            info_panel('Private IP', network.private_ip)
        with b:
            info_panel('Network segment', vm.network_segment)
            info_panel('Simulated public IP', network.public_ip or 'None')
    st.caption(f'Host: {vm.Host} · VM type: {vm.Type} · {len(network.open_ports)} configured ports')
    section_header('Configured services & firewall rules', 'Rules are shown as configured; repeated rules remain visible.')
    entries = []
    for port, detail in sorted(network.open_ports.items()):
        matches = [r for r in network.firewall_rules if r.get('port') == port]
        if not matches:
            entries.append({'Port': port, 'Protocol': detail['protocol'], 'Service': detail['service'],
                            'Allowed source': 'No rule', 'Action': 'Unknown'})
        for rule in matches:
            entries.append({'Port': port, 'Protocol': detail['protocol'], 'Service': detail['service'],
                            'Allowed source': rule.get('source', ''), 'Action': rule.get('action', '')})
    html_table(entries, ['Port', 'Protocol', 'Service', 'Allowed source', 'Action'],
               [.12, .15, .26, .32, .15], empty='This VM has no configured open ports.')
    subset = [f for f in findings if f['vm'] == chosen]
    section_header('Assessment findings', f'{len(subset)} assessed ports · expand a finding for complete reasoning')
    finding_table(subset)
    for f in subset:
        with st.expander(finding_title(f)):
            finding_detail(f)

elif page == 'Risk Findings':
    page_header('Assessment / findings', 'Risk findings',
                'Filter security findings and examine the full context behind each assessment.')
    a, b = st.columns([1, 1.2], gap='medium')
    with a:
        selected = st.multiselect('Severity', RISK_ORDER, default=RISK_ORDER)
    with b:
        selected_vms = st.multiselect('Virtual machines', [v.name for v in vms], placeholder='All virtual machines')
    search = st.text_input('Search VM, role, service, source, exposure or recommendation',
                           placeholder='Search findings, e.g. SSH or 0.0.0.0/0')
    filtered = df[df['risk_level'].isin(selected)].copy()
    if selected_vms:
        filtered = filtered[filtered['vm'].isin(selected_vms)]
    if search.strip():
        cols = ['vm', 'role', 'service', 'firewall_source', 'exposure', 'recommendation']
        mask = filtered[cols].fillna('').astype(str).apply(
            lambda x: x.str.contains(search.strip(), case=False, regex=False)).any(axis=1)
        filtered = filtered[mask]
    priority = {'High': 0, 'Medium': 1, 'Low': 2, 'Review Required': 3}
    filtered['_order'] = filtered['risk_level'].map(priority)
    filtered = filtered.sort_values(['_order', 'vm', 'port'])
    st.markdown(f'<span class="ps-count">{len(filtered)} of {len(findings)} findings</span>', unsafe_allow_html=True)
    finding_table(filtered.to_dict('records'), include_role=True)
    if not filtered.empty:
        section_header('Finding detail', 'Choose a finding to read its full exposure, policy reasoning and recommendation.')
        options = list(filtered.index)
        idx = st.selectbox('Inspect a finding', options,
                           format_func=lambda idx: finding_title(df.loc[idx].to_dict()))
        finding_detail(df.loc[idx].to_dict())

elif page == 'Remediation':
    page_header('Simulation / firewall', 'Firewall remediation simulator',
                'Preview a proposed firewall source change safely, then compare assessments before and after.')
    st.info('Simulation only: the change is applied to a temporary VM copy. Original VM configuration and report exports stay unchanged.', icon='🔒')
    names = [vm.name for vm in vms if vm.network.open_ports]
    a, b = st.columns(2, gap='medium')
    with a:
        chosen = st.selectbox('Virtual machine', names,
                              format_func=lambda n: f'{n} — {vm_by_name[n].role}', key='rem_vm')
    vm = vm_by_name[chosen]
    with b:
        port = st.selectbox('Configured port', sorted(vm.network.open_ports),
                            format_func=lambda p: f"{p}/{vm.network.open_ports[p]['protocol']} — {vm.network.open_ports[p]['service']}",
                            key='rem_port')
    fw = evaluate_firewall(vm, port)
    details_grid([('Current firewall status', fw['status']), ('Current allowed source', fw['source'])])
    possible = fw['status'] in ('Broad Allow', 'Restricted Allow') and fw['rule_count'] == 1
    if not possible:
        st.warning('This port cannot be automatically remediated: it does not have one unambiguous ALLOW rule.')
    suggestions = {
        'Management': '10.0.4.0/24', 'Application': '10.0.2.0/24',
        'Monitoring': '10.0.5.0/24', 'Database': '10.0.3.0/24',
    }
    svc = vm.network.open_ports[port]['service']
    default = '10.0.4.0/24' if svc == 'SSH' else (
        '10.0.2.0/24' if svc in ('MySQL', 'PostgreSQL', 'API', 'Application') else '10.0.4.0/24')
    with st.form('remediate_form'):
        source = st.text_input('Proposed allowed source (IPv4 CIDR)', value=default,
                               help='The new source must be a strict subset of the currently allowed range.')
        st.caption('Enter an IPv4 subnet in CIDR notation. The engine validates network policy and the proposed source.')
        submit = st.form_submit_button('Apply to copy & reassess', disabled=not possible,
                                       type='primary', use_container_width=True)
    if submit:
        try:
            preview = simulate_firewall_remediation(vm, port, source.strip())
            st.session_state.remediation_preview = preview
        except (ValueError, RuntimeError) as exc:
            st.session_state.remediation_preview = None
            st.error(f'Change rejected: {exc}')
    if st.button('Reset comparison', use_container_width=True):
        st.session_state.remediation_preview = None
        st.rerun()
    preview = st.session_state.remediation_preview
    if preview and (preview['vm'] != chosen or preview['port'] != port):
        st.session_state.remediation_preview = None
        preview = None
    if preview:
        before, after = preview['before'], preview['after']
        rows = [('Allowed source', before['firewall_source'], after['firewall_source']),
                ('Firewall status', before['firewall_status'], after['firewall_status']),
                ('Exposure', before['exposure'], after['exposure']),
                ('Policy compliant', before['policy_compliant'], after['policy_compliant']),
                ('Risk score', before['risk_score'], after['risk_score']),
                ('Risk classification', before['risk_level'], after['risk_level']),
                ('Recommendation', before['recommendation'], after['recommendation'])]
        section_header('Before / after comparison', 'All values are generated by the existing assessment and remediation engines.')
        html_table([{'Metric': label, 'Before': old, 'After': new} for label, old, new in rows],
                   ['Metric', 'Before', 'After'], [.2, .4, .4])
        if before['risk_score'] is not None and after['risk_score'] is not None:
            delta = before['risk_score'] - after['risk_score']
            st.metric('Risk score reduction', delta)
            if delta <= 0:
                st.warning('This change did not reduce the numeric risk score. Check policy compliance and service requirements.')
        st.success('Original configuration preserved. Only a temporary VM copy was assessed.')

else:  # Reports
    page_header('Exports / reporting', 'Assessment reports',
                'Download current baseline findings and an audit-friendly assessment summary.')
    risk_summary()
    col_a, col_b = st.columns(2, gap='large')
    with col_a:
        st.markdown('<div class="ps-panel"><h4>CSV findings</h4><p>Structured per-port data including scores, explanations, network context and recommendations. Suitable for spreadsheet review.</p></div>', unsafe_allow_html=True)
        st.download_button('Download findings CSV', data=cached_csv(findings),
                           file_name='port_risk_findings.csv', mime='text/csv', use_container_width=True)
    with col_b:
        st.markdown('<div class="ps-panel"><h4>PDF assessment</h4><p>Shareable assessment covering scope, summary, complete findings, recommendations and assessment limitations.</p></div>', unsafe_allow_html=True)
        try:
            pdf = assessment_pdf(assessment)
            st.download_button('Download PDF report', data=pdf, file_name='port_risk_assessment.pdf',
                               mime='application/pdf', use_container_width=True)
        except Exception as exc:
            st.error(f'PDF generation unavailable: {exc}')
    st.divider()
    section_header('Included assessment data', f'{len(findings)} findings from the current session baseline')
    finding_table(findings, include_role=True)
    if findings:
        with st.expander('Review full exported finding details'):
            export_index = st.selectbox('Exported finding', range(len(findings)),
                                        format_func=lambda i: finding_title(findings[i]), key='report_finding')
            finding_detail(findings[export_index])
    st.caption('Exports always reflect the current baseline assessment; remediation previews are not applied to reports.')
