"""Non-destructive firewall-source restriction; never edits the supplied VM."""
from copy import deepcopy
import ipaddress
from core.firewall import evaluate_firewall
from core.risk_engine import calculate_enhanced_risk
from core.recommendations import generate_enhanced_recommendation

def simulate_firewall_remediation(vm,port,new_source):
    if vm.network is None or port not in vm.network.open_ports:raise ValueError("Unknown VM port")
    proposed=ipaddress.ip_network(new_source,strict=True)
    if proposed.version!=4 or proposed.prefixlen==0:raise ValueError("A restricted IPv4 subnet is required")
    before=evaluate_firewall(vm,port)
    if before["review_required"] or before["status"] not in ("Broad Allow","Restricted Allow"):
        raise ValueError("Only unambiguous allowed sources can be remediated")
    matches=[r for r in vm.network.firewall_rules if r.get("port")==port]
    if len(matches)!=1 or matches[0].get("action"," ").upper()!="ALLOW":
        raise ValueError("Exactly one ALLOW rule is required")
    current=ipaddress.ip_network(matches[0]["source"],strict=False)
    if not proposed.subnet_of(current) or proposed==current:raise ValueError("Proposed source must narrow existing access")
    copy=deepcopy(vm)
    next(r for r in copy.network.firewall_rules if r["port"]==port)["source"]=str(proposed)
    b=calculate_enhanced_risk(vm,port);a=calculate_enhanced_risk(copy,port)
    # A smaller subnet is not necessarily an authorized subnet.
    # Reject proposed remediation that would leave a known policy violation.
    if a['policy_compliant'] is not True or a['review_required']:
        raise ValueError('Proposed source does not satisfy the service access policy')
    return {"vm":vm.name,"port":port,"old_source":str(current),"new_source":str(proposed),
            "before":{**b,"recommendation":generate_enhanced_recommendation(b)},
            "after":{**a,"recommendation":generate_enhanced_recommendation(a)},"modified_vm":copy}
