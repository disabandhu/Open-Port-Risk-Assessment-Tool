def generate_enhanced_recommendation(result):
    if result is None: return "No assessment result available."
    s=result["service"]
    if result["review_required"]:
        return "Review missing, invalid, or conflicting firewall rules; verify effective access."
    if result["firewall_status"]=="Blocked":
        return "Maintain the deny rule unless access is explicitly required."
    if result["policy_violation"]=="Excessive Network Exposure":
        return f"Restrict {s} to its approved source networks."
    if result["policy_violation"]=="Unauthorized Source Network":
        return "Replace unapproved source ranges with authorized networks."
    if s=="HTTP":return "Prefer HTTPS for sensitive communication and redirect HTTP where appropriate."
    if s=="HTTPS":return "Maintain valid TLS certificates, current TLS settings, and access controls."
    if s in ("FTP","Telnet"):return "Replace legacy protocols with secure alternatives such as SFTP or SSH."
    if s in ("MySQL","PostgreSQL"):return "Maintain database restrictions to approved application clients."
    if s=="SSH":return "Maintain management-only access, strong authentication, and logs."
    if s in ("Prometheus","Node Exporter"):return "Keep monitoring endpoints internal and restricted."
    if s=="Rsync":return "Restrict backup access and protect stored data and credentials."
    return "Maintain the current access policy and review the service periodically."
