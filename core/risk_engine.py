from core.discovery import identify_service
from core.firewall import evaluate_firewall
from core.policies import SERVICE_POLICIES, evaluate_service_policy

def calculate_enhanced_risk(vm, port):
    service_info=identify_service(vm,port)
    if service_info is None: return None
    firewall=evaluate_firewall(vm,port)
    policy=evaluate_service_policy(service_info["service"],firewall)
    service=service_info["service"]
    meta={**service_info,"role":vm.role,"segment":vm.network_segment,
          "firewall_status":firewall["status"],"firewall_source":firewall["source"],
          "firewall_action":firewall["action"],"policy_compliant":policy["compliant"],
          "policy_violation":policy["violation"]}
    if firewall["review_required"] or policy["review_required"]:
        return {**meta,"exposure":"Uncertain","risk_score":None,"risk_level":"Review Required",
                "review_required":True,"reasons":[policy["details"],*firewall["issues"]]}
    if firewall["status"]=="Blocked":
        return {**meta,"exposure":"Blocked","risk_score":0,"risk_level":"Low",
                "review_required":False,"reasons":["Configured firewall rules block access."]}
    base,exposure_type,_=SERVICE_POLICIES[service]
    score=base
    reasons=[f"Base concern score for {service}: {base}."]
    if policy["compliant"] and firewall["status"]=="Restricted Allow" and exposure_type!="public":
        score-=2
        reasons.append("Access restricted to approved source networks.")
    if policy["compliant"] is False:
        score+=4
        reasons.append(policy["details"])
        if vm.network.public_ip and exposure_type!="public" and firewall["status"]=="Broad Allow":
            score+=2
            reasons.append("Sensitive service broadly exposed on publicly addressed VM.")
    score=max(0,score)
    level="Low" if score<=2 else "Medium" if score<=4 else "High"
    exposure=("Public" if vm.network.public_ip else "Private") + (" / Broad Exposure" if firewall["status"]=="Broad Allow" else " / Restricted Exposure")
    return {**meta,"exposure":exposure,"risk_score":score,"risk_level":level,
            "review_required":False,"reasons":reasons}
