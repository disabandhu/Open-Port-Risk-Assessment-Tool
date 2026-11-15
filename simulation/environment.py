"""Reproduces the Phase B scenario configuration without Colab dependencies.

Documentation-only public IPs and simulated firewall rules: no real cloud deployment.
"""
from core.models import VM, NetworkConfig

NETWORK_SEGMENTS = {
    "DMZ": "10.0.1.0/24", "Application": "10.0.2.0/24",
    "Database": "10.0.3.0/24", "Management": "10.0.4.0/24",
    "Monitoring": "10.0.5.0/24", "Test": "10.0.6.0/24",
}

VM_DEFINITIONS = [
    ("VM1", "host1", "Type_1", "Public Web Server", "DMZ", "10.0.1.10", "203.0.113.10"),
    ("VM2", "host1", "Type_2", "Customer Web Server", "DMZ", "10.0.1.11", "203.0.113.11"),
    ("VM3", "host2", "Type_3", "MySQL Database Server", "Database", "10.0.3.12", None),
    ("VM4", "host2", "Type_1", "Application Server", "Application", "10.0.2.13", "203.0.113.13"),
    ("VM5", "host3", "Type_2", "PostgreSQL Database Server", "Database", "10.0.3.14", None),
    ("VM6", "host3", "Type_3", "Development Server", "Application", "10.0.2.15", "203.0.113.15"),
    ("VM7", "host4", "Type_1", "Internal Application Server", "Application", "10.0.2.16", None),
    ("VM8", "host4", "Type_2", "Public Web Gateway", "DMZ", "10.0.1.17", "203.0.113.17"),
    ("VM9", "host1", "Type_1", "Management Server", "Management", "10.0.4.18", None),
    ("VM10", "host2", "Type_2", "API Server", "DMZ", "10.0.1.19", "203.0.113.19"),
    ("VM11", "host3", "Type_1", "Monitoring Server", "Monitoring", "10.0.5.20", None),
    ("VM12", "host4", "Type_1", "Legacy Server", "DMZ", "10.0.1.21", "203.0.113.21"),
    ("VM13", "host4", "Type_3", "Public Database Server", "Database", "10.0.3.22", "203.0.113.22"),
    ("VM14", "host3", "Type_2", "Backup Server", "Management", "10.0.4.23", None),
    ("VM15", "host1", "Type_1", "Isolated Test Server", "Test", "10.0.6.24", None),
]

# (vm, port, service, source CIDR, firewall action)
SERVICE_CONFIG = [
    ("VM1",22,"SSH","0.0.0.0/0","ALLOW"),("VM1",80,"HTTP","0.0.0.0/0","ALLOW"),("VM1",443,"HTTPS","0.0.0.0/0","ALLOW"),
    ("VM2",80,"HTTP","0.0.0.0/0","ALLOW"),("VM2",443,"HTTPS","0.0.0.0/0","ALLOW"),
    ("VM3",3306,"MySQL","10.0.2.0/24","ALLOW"),
    ("VM4",22,"SSH","10.0.4.0/24","ALLOW"),("VM4",8080,"Application","0.0.0.0/0","ALLOW"),
    ("VM5",5432,"PostgreSQL","10.0.2.0/24","ALLOW"),
    ("VM6",22,"SSH","0.0.0.0/0","ALLOW"),("VM6",443,"HTTPS","0.0.0.0/0","ALLOW"),
    ("VM7",8080,"Application","10.0.2.0/24","ALLOW"),
    ("VM8",80,"HTTP","0.0.0.0/0","ALLOW"),("VM8",443,"HTTPS","0.0.0.0/0","ALLOW"),
    ("VM9",22,"SSH","10.0.4.0/24","ALLOW"),
    ("VM10",443,"HTTPS","0.0.0.0/0","ALLOW"),("VM10",8443,"API","10.0.2.0/24","ALLOW"),("VM10",22,"SSH","10.0.4.0/24","ALLOW"),
    ("VM11",9090,"Prometheus","10.0.4.0/24","ALLOW"),("VM11",9100,"Node Exporter","10.0.5.0/24","ALLOW"),
    ("VM12",21,"FTP","0.0.0.0/0","ALLOW"),("VM12",23,"Telnet","0.0.0.0/0","ALLOW"),("VM12",22,"SSH","10.0.4.0/24","ALLOW"),
    ("VM13",5432,"PostgreSQL","0.0.0.0/0","ALLOW"),("VM13",22,"SSH","10.0.4.0/24","ALLOW"),
    ("VM14",22,"SSH","10.0.4.0/24","ALLOW"),("VM14",873,"Rsync","0.0.0.0/0","DENY"),
]

def load_environment() -> list[VM]:
    """Fresh independent VM objects on each call; never mutate the baseline."""
    vms=[]
    for name,host,typ,role,segment,private,public in VM_DEFINITIONS:
        vm=VM(name,host,typ,role=role,network_segment=segment)
        vm.attach_network(NetworkConfig(private,public))
        vms.append(vm)
    index={v.name:v for v in vms}
    for name,port,service,source,action in SERVICE_CONFIG:
        index[name].network.add_service(port,"TCP",service)
        index[name].network.add_firewall_rule(port,source,action)
    return vms
