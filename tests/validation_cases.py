"""Scenario-based acceptance checks shared by unittest and the CSV matrix exporter.

Expected values are explicitly defined; actual results are computed afresh.
"""
import copy
import socket
from contextlib import closing
from dataclasses import dataclass

from simulation.environment import load_environment
from core.assessment import assess_enhanced_vm, run_security_assessment
from core.discovery import discover_ports, identify_service
from core.firewall import evaluate_firewall
from core.risk_engine import calculate_enhanced_risk
from core.remediation import simulate_firewall_remediation
from core.scanner import scan_local_port
from core.reporting import findings_csv, assessment_pdf


@dataclass
class Case:
    name: str
    input: str
    expected: str
    actual: str
    category: str
    observation: str = ''

    @property
    def status(self):
        return 'PASSED' if self.actual == self.expected else 'FAILED'


def build_cases():
    vms = load_environment()
    lookup = {vm.name: vm for vm in vms}
    cases = []

    def add(category, name, inputs, expected, actual, observation=''):
        cases.append(Case(name, inputs, str(expected), str(actual), category, observation))

    report = run_security_assessment(vms)
    add('Integration', 'VM count', 'load_environment()', 15, len(vms))
    add('Integration', 'Configured ports', 'all VMs', 27, report['summary']['configured_ports'])
    add('Integration', 'Finding count', 'run_security_assessment()', 27, len(report['findings']))
    add('Integration', 'Unique VM/port identities', 'findings', 27,
        len({(r['vm'], r['port']) for r in report['findings']}))
    add('Integration', 'All risk counts accounted for', 'summary', 27,
        sum(report['summary'][k] for k in ('High','Medium','Low','Review Required')))
    add('Integration', 'VM15 has no findings', 'VM15', 0, len(assess_enhanced_vm(lookup['VM15'])))

    for name, port, expected in [
        ('VM1',22,'High'), ('VM2',443,'Low'), ('VM2',80,'Medium'),
        ('VM3',3306,'Low'),('VM7',8080,'Low'),('VM12',23,'High'),
        ('VM13',5432,'High'),('VM14',873,'Low')
    ]:
        f = calculate_enhanced_risk(lookup[name], port)
        add('Policy', f'{name}:{port} classification', f'{name}:{port}', expected, f['risk_level'])
    add('Firewall','Blocked backup port','VM14:873','Blocked',evaluate_firewall(lookup['VM14'],873)['status'])
    add('Firewall','Restricted database','VM3:3306','Restricted Allow',evaluate_firewall(lookup['VM3'],3306)['status'])

    for label, edit, expected in [
        ('Missing firewall rule',lambda vm: setattr(vm.network,'firewall_rules',[r for r in vm.network.firewall_rules if r['port'] != 22]),'Missing Rule'),
        ('Conflicting ALLOW/DENY',lambda vm: vm.network.add_firewall_rule(22,'10.0.4.0/24','DENY'),'Conflicting Rules'),
        ('Malformed CIDR',lambda vm: vm.network.firewall_rules.__setitem__(0,{**vm.network.firewall_rules[0],'source':'bad-cidr'}),'Invalid Configuration'),
        ('Invalid firewall action',lambda vm: vm.network.firewall_rules.__setitem__(0,{**vm.network.firewall_rules[0],'action':'MAYBE'}),'Invalid Configuration'),
    ]:
        vm = copy.deepcopy(lookup['VM1'])
        edit(vm)
        fw = evaluate_firewall(vm,22)
        add('Firewall',label,'copied VM1:22',expected,fw['status'])
        add('Firewall',label+' review','copied VM1:22',True,fw['review_required'])

    partial = copy.deepcopy(lookup['VM14'])
    next(r for r in partial.network.firewall_rules if r['port']==873)['source']='10.0.4.0/24'
    add('Firewall','Partial DENY is not fully blocked','VM14:873, limited DENY',True,evaluate_firewall(partial,873)['review_required'])

    missing = copy.deepcopy(lookup['VM1'])
    missing.network = None
    add('Robustness','Missing network yields no discovery','VM1 network=None',0,len(discover_ports(missing)))
    add('Robustness','Missing network yields no findings','VM1 network=None',0,len(assess_enhanced_vm(missing)))
    add('Robustness','Unknown service port','VM1:9999',None,identify_service(lookup['VM1'],9999))
    add('Robustness','Empty port inventory','VM15',0,len(discover_ports(lookup['VM15'])))

    before_rules = copy.deepcopy(lookup['VM1'].network.firewall_rules)
    fixed = simulate_firewall_remediation(lookup['VM1'],22,'10.0.4.0/24')
    add('Remediation','Before score','VM1:22',8,fixed['before']['risk_score'])
    add('Remediation','After score','VM1:22, management only',0,fixed['after']['risk_score'])
    add('Remediation','Before level','VM1:22','High',fixed['before']['risk_level'])
    add('Remediation','After level','VM1:22, management only','Low',fixed['after']['risk_level'])
    add('Remediation','Original VM unchanged','VM1:22',True,before_rules == lookup['VM1'].network.firewall_rules)

    for source in ('bad-cidr','0.0.0.0/0','10.1.1.0/24'):
        try:
            simulate_firewall_remediation(lookup['VM1'],22,source)
            outcome='ACCEPTED'
        except ValueError:
            outcome='REJECTED'
        add('Remediation','Reject invalid or non-narrowing CIDR',f'VM1:22 => {source}','REJECTED',outcome)

    for port in (0,65536,True,'22',-1):
        try:
            scan_local_port(port)
            outcome='ACCEPTED'
        except ValueError:
            outcome='REJECTED'
        add('Localhost','Reject invalid TCP port',repr(port),'REJECTED',outcome)
    for timeout in (0,-1,6,float('nan'),'invalid',None):
        try:
            scan_local_port(12345,timeout=timeout)
            outcome='ACCEPTED'
        except ValueError:
            outcome='REJECTED'
        add('Localhost','Reject invalid timeout',repr(timeout),'REJECTED',outcome)

    with closing(socket.socket(socket.AF_INET,socket.SOCK_STREAM)) as listener:
        listener.bind(('127.0.0.1',0))
        listener.listen(3)
        p = listener.getsockname()[1]
        open_result = scan_local_port(p)
        add('Localhost','Live TCP listener detected','127.0.0.1, ephemeral listener','OPEN',open_result['status'],f'Allocated test port: {p}')
    closed_result = scan_local_port(p)
    add('Localhost','Stopped listener is closed','127.0.0.1, listener stopped','CLOSED',closed_result['status'],f'Allocated test port: {p}')

    csv_payload=findings_csv(report['findings'])
    add('Reporting','CSV contains data','27 findings',True,len(csv_payload)>1000)
    add('Reporting','PDF header valid','assessment_pdf(report)',True,assessment_pdf(report).startswith(b'%PDF-'))
    return cases
