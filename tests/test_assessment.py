import copy
import ipaddress
import unittest
from simulation.environment import load_environment, NETWORK_SEGMENTS
from core.assessment import run_security_assessment,assess_enhanced_vm
from core.risk_engine import calculate_enhanced_risk
from core.firewall import evaluate_firewall
from core.remediation import simulate_firewall_remediation

class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.vms=load_environment()
        self.byname={vm.name:vm for vm in self.vms}
    def test_inventory(self):
        self.assertEqual(len(self.vms),15)
        self.assertEqual(sum(len(vm.network.open_ports) for vm in self.vms),27)
        self.assertEqual(len(self.byname),15)
        self.assertEqual(len({v.network.private_ip for v in self.vms}),15)
        for vm in self.vms:self.assertIn(ipaddress.ip_address(vm.network.private_ip),ipaddress.ip_network(NETWORK_SEGMENTS[vm.network_segment]))
    def test_complete_assessment(self):
        out=run_security_assessment(self.vms)
        self.assertEqual(out['summary']['findings'],27)
        self.assertEqual(len({(f['vm'],f['port']) for f in out['findings']}),27)
        self.assertEqual(sum(out['summary'][k] for k in ('High','Medium','Low','Review Required')),27)
    def test_scenario_classifications(self):
        cases=[('VM1',22,'High'),('VM2',443,'Low'),('VM2',80,'Medium'),('VM3',3306,'Low'),
               ('VM7',8080,'Low'),('VM12',23,'High'),('VM13',5432,'High'),('VM14',873,'Low')]
        for name,port,expected in cases:
            with self.subTest(vm=name,port=port):
                self.assertEqual(calculate_enhanced_risk(self.byname[name],port)['risk_level'],expected)
    def test_missing_conflicting_invalid(self):
        for case in ('missing','conflict','invalid'):
            vm=copy.deepcopy(self.byname['VM1'])
            if case=='missing':vm.network.firewall_rules=[r for r in vm.network.firewall_rules if r['port']!=22]
            elif case=='conflict':vm.network.add_firewall_rule(22,'10.0.4.0/24','DENY')
            else:next(r for r in vm.network.firewall_rules if r['port']==22)['source']='nonsense'
            self.assertEqual(calculate_enhanced_risk(vm,22)['risk_level'],'Review Required')
    def test_empty_missing(self):
        vm=copy.deepcopy(self.byname['VM15']);self.assertEqual(assess_enhanced_vm(vm),[])
        vm.network=None;self.assertEqual(assess_enhanced_vm(vm),[])
    def test_remediation_non_destructive(self):
        vm=self.byname['VM1'];original=copy.deepcopy(vm.network.firewall_rules)
        change=simulate_firewall_remediation(vm,22,'10.0.4.0/24')
        self.assertEqual(change['before']['risk_level'],'High')
        self.assertEqual(change['after']['risk_level'],'Low')
        self.assertEqual(vm.network.firewall_rules,original)
        self.assertNotEqual(change['modified_vm'].network.firewall_rules,original)
    def test_data_independence(self):
        a=load_environment();b=load_environment()
        a[0].network.firewall_rules[0]['source']='10.0.4.0/24'
        self.assertEqual(b[0].network.firewall_rules[0]['source'],'0.0.0.0/0')
    def test_partial_deny_unknown(self):
        vm=copy.deepcopy(self.byname['VM14'])
        rule=next(r for r in vm.network.firewall_rules if r['port']==873)
        rule['source']='10.0.4.0/24'
        self.assertTrue(evaluate_firewall(vm,873)['review_required'])

if __name__=='__main__':unittest.main()
