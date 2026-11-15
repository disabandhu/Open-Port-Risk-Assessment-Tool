"""Command-line entry point: python main.py [--export]"""
import argparse
import csv
import json
from pathlib import Path
from simulation.environment import load_environment
from core.assessment import run_security_assessment

def main():
    parser=argparse.ArgumentParser(description="Simulated open-port risk assessment")
    parser.add_argument("--export",action="store_true",help="Write CSV and JSON reports")
    args=parser.parse_args()
    result=run_security_assessment(load_environment())
    summary=result["summary"]
    print("OPEN PORT RISK ASSESSMENT — ENHANCED SIMULATION")
    for key,value in summary.items(): print(f"{key:20} {value}")
    print("\nVM     PORT    SERVICE          RISK             SCORE")
    for f in result["findings"]:
        print(f"{f['vm']:<6} {f['port']:<7} {f['service']:<16} {f['risk_level']:<16} {str(f['risk_score']):<5}")
    if args.export:
        directory=Path('reports');directory.mkdir(exist_ok=True)
        with (directory/'assessment.json').open('w') as out:json.dump(result,out,indent=2)
        rows=result["findings"]
        with (directory/'findings.csv').open('w',newline='') as out:
            writer=csv.DictWriter(out,fieldnames=rows[0].keys());writer.writeheader();writer.writerows(rows)
        print("\nSaved reports/assessment.json and reports/findings.csv")

if __name__=='__main__':main()
