import ipaddress
from simulation.environment import NETWORK_SEGMENTS

SERVICE_POLICIES = {
    "HTTPS":(1,"public",["DMZ","Application"]),
    "HTTP":(3,"public",["DMZ"]),
    "API":(2,"restricted",["Application","Management"]),
    "Application":(2,"restricted",["Application"]),
    "SSH":(2,"restricted",["Management"]),
    "MySQL":(3,"restricted",["Application"]),
    "PostgreSQL":(3,"restricted",["Application"]),
    "Prometheus":(2,"restricted",["Management","Monitoring"]),
    "Node Exporter":(2,"restricted",["Monitoring","Management"]),
    "Rsync":(2,"restricted",["Management"]),
    "FTP":(5,"legacy",["Management"]),
    "Telnet":(6,"legacy",["Management"]),
}

def evaluate_service_policy(service, firewall):
    policy=SERVICE_POLICIES.get(service)
    if policy is None:
        return {"compliant":None,"violation":"Unknown Service Policy","details":"No policy is defined for this service.","review_required":True}
    if firewall["review_required"]:
        return {"compliant":None,"violation":"Uncertain Firewall Configuration","details":"Effective access cannot be confirmed.","review_required":True}
    if firewall["status"]=="Blocked":
        return {"compliant":True,"violation":None,"details":"Access is blocked by configured rule.","review_required":False}
    _,exposure,segments=policy
    if exposure=="public":
        return {"compliant":True,"violation":None,"details":"Source scope permitted for this public-facing service.","review_required":False}
    if firewall["status"]=="Broad Allow":
        return {"compliant":False,"violation":"Excessive Network Exposure","details":"Service should not accept all IPv4 sources.","review_required":False}
    approved=[ipaddress.ip_network(NETWORK_SEGMENTS[s]) for s in segments]
    sources=[ipaddress.ip_network(s) for s in firewall["allowed_sources"]]
    allowed=bool(sources) and all(any(s.subnet_of(a) for a in approved) for s in sources)
    if allowed:
        return {"compliant":True,"violation":None,"details":"Access limited to approved segments.","review_required":False}
    return {"compliant":False,"violation":"Unauthorized Source Network","details":"Source extends outside approved segments.","review_required":False}
