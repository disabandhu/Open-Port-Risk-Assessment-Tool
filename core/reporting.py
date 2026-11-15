"""Pure reporting helpers for assessments. No Streamlit dependency."""
import csv
import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

FINDING_COLUMNS = [
    'vm', 'role', 'segment', 'private_ip', 'public_ip', 'port', 'protocol',
    'service', 'firewall_status', 'firewall_source', 'firewall_action',
    'exposure', 'policy_compliant', 'policy_violation', 'risk_score',
    'risk_level', 'review_required', 'reasons', 'recommendation'
]


def findings_csv(findings):
    """Return a UTF-8 CSV payload with deterministic column order."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FINDING_COLUMNS, extrasaction='ignore')
    writer.writeheader()
    for item in findings:
        row = dict(item)
        row['reasons'] = ' | '.join(item.get('reasons') or [])
        writer.writerow(row)
    return buffer.getvalue().encode('utf-8-sig')


def assessment_pdf(assessment):
    """Create a concise paginated PDF from current computed findings."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=17*mm, rightMargin=17*mm,
        topMargin=17*mm, bottomMargin=17*mm, title='Open Port Risk Assessment'
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='SmallCellX', parent=styles['Normal'], fontSize=7.5, leading=10, spaceAfter=0))
    styles.add(ParagraphStyle(name='FineX', parent=styles['Normal'], fontSize=8.5, leading=12))
    styles.add(ParagraphStyle(name='FindingTitleX', parent=styles['Heading3'], spaceBefore=9, spaceAfter=4))
    cell = styles['SmallCellX']
    para = lambda value: Paragraph(escape(str(value if value is not None else '—')), cell)
    story = [Paragraph('Open Port Risk Assessment', styles['Title']),
             Paragraph('Simulated cloud infrastructure · Configuration-based assessment', styles['FineX']),
             Spacer(1, 5*mm)]
    s = assessment['summary']
    metrics = [('Virtual machines',s['vms']),('Configured ports',s['configured_ports']),
               ('Findings',s['findings']),('High',s['High']),('Medium',s['Medium']),
               ('Low',s['Low']),('Review Required',s['Review Required'])]
    table = Table([[para('Metric'),para('Value')]] + [[para(k),para(v)] for k,v in metrics], colWidths=[93*mm,72*mm])
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#E8EEF4')),
        ('GRID',(0,0),(-1,-1),0.35,colors.HexColor('#CCD5DF')),
        ('VALIGN',(0,0),(-1,-1),'TOP'), ('TOPPADDING',(0,0),(-1,-1),5),
        ('BOTTOMPADDING',(0,0),(-1,-1),5)
    ]))
    story.extend([table, Spacer(1,5*mm), Paragraph('Assessment findings',styles['Heading2'])])
    priority={'High':0,'Medium':1,'Low':2,'Review Required':3}
    findings=sorted(assessment['findings'],key=lambda f:(priority.get(f['risk_level'],9),f['vm'],f['port']))
    for f in findings:
        title=f"{f['vm']} · {f['port']}/{f['protocol']} · {f['service']} — {f['risk_level']}"
        lines=[
            f"Role: {f['role']}  |  Segment: {f['segment']}",
            f"Address: {f['private_ip']}  |  Simulated public IP: {f['public_ip'] or 'None'}",
            f"Firewall: {f['firewall_status']}  |  Source: {f['firewall_source']}",
            f"Risk score: {f['risk_score'] if f['risk_score'] is not None else 'Not assigned'}  |  Policy compliant: {f['policy_compliant']}",
            'Reason: ' + '; '.join(f.get('reasons') or []),
            'Recommendation: ' + f['recommendation']
        ]
        story.append(KeepTogether([Paragraph(escape(title), styles['FindingTitleX'])] +
                                    [Paragraph(escape(line),styles['FineX']) for line in lines]))
    story.extend([Spacer(1,5*mm),Paragraph('Scope and limitations',styles['Heading2']),
        Paragraph('Cloud VM configurations are simulated. 203.0.113.0/24 contains documentation-only public addresses. '
                  'Firewall decisions are based on a simplified policy model, not live connectivity. '
                  'Risk scores are project-specific heuristics, not CVSS or verified vulnerabilities.', styles['FineX'])])
    def footer(canvas, document):
        canvas.saveState();canvas.setFont('Helvetica',8);canvas.setFillColor(colors.grey)
        canvas.drawRightString(A4[0]-17*mm,11*mm,f'Page {document.page}')
        canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return buffer.getvalue()
