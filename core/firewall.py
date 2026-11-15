import ipaddress

def evaluate_firewall(vm, port):
    if vm.network is None or port not in vm.network.open_ports:
        return None
    rules=[r for r in vm.network.firewall_rules if r.get("port")==port]
    result={"status":"Unknown","action":"Unknown","source":"Unknown", "allowed_sources":[],
            "rule_count":len(rules),"review_required":False,"issues":[]}
    if not rules:
        result.update(status="Missing Rule",source="No matching rule",review_required=True)
        result["issues"].append("No firewall rule is configured for this port.")
        return result
    parsed=[]
    for rule in rules:
        action=str(rule.get("action","")).strip().upper()
        source=str(rule.get("source","")).strip()
        if action not in ("ALLOW","DENY"):
            result["issues"].append(f"Invalid firewall action: {action}"); continue
        try:
            net=ipaddress.ip_network(source,strict=False)
            if net.version!=4: raise ValueError("IPv6 unsupported")
        except ValueError:
            result["issues"].append(f"Invalid source network: {source}"); continue
        parsed.append((action,net))
    if result["issues"]:
        result.update(status="Invalid Configuration",source="Invalid or incomplete rules",review_required=True)
        return result
    allows=[n for a,n in parsed if a=="ALLOW"]
    denies=[n for a,n in parsed if a=="DENY"]
    if any(a.overlaps(d) for a in allows for d in denies):
        result.update(status="Conflicting Rules",source="Overlapping ALLOW/DENY",review_required=True)
        result["issues"].append("ALLOW and DENY ranges overlap; rule precedence undefined.")
        return result
    if not allows:
        # Conservative handling: deny-only ranges are not necessarily all-source blocking.
        # Restrict 'Blocked' status to a full IPv4 deny, or explicitly modeled deny-only policy.
        if any(n == ipaddress.ip_network('0.0.0.0/0') for n in denies):
            result.update(status="Blocked",action="DENY",source=", ".join(map(str,denies)))
        else:
            result.update(status="Review Required",source=", ".join(map(str,denies)),review_required=True)
            result["issues"].append("Partial DENY with unspecified default action.")
        return result
    sources=list(ipaddress.collapse_addresses(allows))
    result.update(status="Broad Allow" if ipaddress.ip_network('0.0.0.0/0') in sources else "Restricted Allow",
                  action="ALLOW",source=", ".join(map(str,sources)),allowed_sources=list(map(str,sources)))
    return result
