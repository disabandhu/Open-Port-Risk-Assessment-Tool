from collections import Counter
from core.discovery import discover_ports
from core.risk_engine import calculate_enhanced_risk
from core.recommendations import generate_enhanced_recommendation

def assess_enhanced_vm(vm):
    findings=[]
    for entry in discover_ports(vm):
        result=calculate_enhanced_risk(vm,entry["port"])
        if result is None: raise RuntimeError(f"Could not assess {vm.name}:{entry['port']}")
        findings.append({**result,"recommendation":generate_enhanced_recommendation(result)})
    return findings

def assess_enhanced_all(vms):
    return [finding for vm in vms for finding in assess_enhanced_vm(vm)]

def run_security_assessment(vms):
    findings=assess_enhanced_all(vms)
    expected=sum(len(vm.network.open_ports) if vm.network else 0 for vm in vms)
    if len(findings)!=expected:raise RuntimeError("Finding count does not match inventory")
    counts=Counter(f["risk_level"] for f in findings)
    return {"findings":findings,"summary":{
        "vms":len(vms),"configured_ports":expected,"findings":len(findings),
        **{k:counts.get(k,0) for k in ("High","Medium","Low","Review Required")}}}
