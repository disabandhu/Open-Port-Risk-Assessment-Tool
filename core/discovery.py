def discover_ports(vm):
    """Read configured simulated open-port inventory; not a live TCP scan."""
    if vm.network is None:
        return []
    return [{"vm":vm.name,"private_ip":vm.network.private_ip,"public_ip":vm.network.public_ip,
             "port":p,"protocol":d["protocol"]} for p,d in sorted(vm.network.open_ports.items())]

def identify_service(vm, port):
    if vm.network is None or port not in vm.network.open_ports:
        return None
    entry=vm.network.open_ports[port]
    return {"vm":vm.name,"private_ip":vm.network.private_ip,"public_ip":vm.network.public_ip,
            "port":port,"protocol":entry["protocol"],"service":entry["service"]}
