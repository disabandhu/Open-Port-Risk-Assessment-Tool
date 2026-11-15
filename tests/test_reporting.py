import csv
import io
import unittest
from core.assessment import run_security_assessment
from core.reporting import findings_csv, assessment_pdf
from simulation.environment import load_environment

class ReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output=run_security_assessment(load_environment())

    def test_csv_contains_computed_findings(self):
        payload=findings_csv(self.output['findings'])
        rows=list(csv.DictReader(io.StringIO(payload.decode('utf-8-sig'))))
        self.assertEqual(len(rows),27)
        ssh=next(r for r in rows if r['vm']=='VM1' and r['port']=='22')
        self.assertEqual(ssh['risk_level'],'High')
        self.assertEqual(ssh['firewall_source'],'0.0.0.0/0')
        self.assertTrue(ssh['recommendation'])

    def test_pdf_contains_paginated_report(self):
        payload=assessment_pdf(self.output)
        self.assertTrue(payload.startswith(b'%PDF-'))
        self.assertGreater(len(payload),3000)
        from reportlab.pdfbase.pdfdoc import PDFDocument
        from pypdf import PdfReader
        pages=PdfReader(io.BytesIO(payload)).pages
        content=' '.join(p.extract_text() for p in pages)
        self.assertIn('VM1',content)
        self.assertIn('Scope and limitations',content)
        self.assertIn('PostgreSQL',content)

    def test_repeatable_reporting(self):
        self.assertEqual(findings_csv(self.output['findings']),findings_csv(self.output['findings']))

if __name__=='__main__':unittest.main()
