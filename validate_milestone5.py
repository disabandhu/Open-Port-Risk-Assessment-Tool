"""Run acceptance scenarios and export genuine expected/actual observations.

Usage: python validate_milestone5.py
"""
import csv
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from tests.validation_cases import build_cases


def main():
    cases=build_cases()
    target=Path('reports')
    target.mkdir(exist_ok=True)
    columns=['category','name','input','expected','actual','status','observation']
    filename=target/'milestone5_test_matrix.csv'
    with filename.open('w',newline='',encoding='utf-8-sig') as handle:
        writer=csv.DictWriter(handle,fieldnames=columns)
        writer.writeheader()
        for case in cases:
            writer.writerow({**asdict(case),'status':case.status})
    summary={'executed_at_utc':datetime.now(timezone.utc).isoformat(),
             'total':len(cases),'passed':sum(c.status=='PASSED' for c in cases),
             'failed':sum(c.status!='PASSED' for c in cases),
             'by_category':dict(Counter(c.category for c in cases))}
    (target/'milestone5_summary.json').write_text(json.dumps(summary,indent=2))
    for case in cases:
        print(f'{case.status:<7} | {case.category:<12} | {case.name}: {case.actual}')
    print(f"\nResult: {summary['passed']}/{summary['total']} passed; {summary['failed']} failed")
    print('Matrix:',filename)
    if summary['failed']:
        raise SystemExit(1)


if __name__=='__main__':
    main()
