from dataclasses import dataclass, field

@dataclass
class NetworkConfig:
    private_ip: str
    public_ip: str | None = None
    open_ports: dict[int, dict] = field(default_factory=dict)
    firewall_rules: list[dict] = field(default_factory=list)

    def add_service(self, port: int, protocol: str, service: str) -> None:
        self.open_ports[port] = {"protocol": protocol, "service": service}

    def add_firewall_rule(self, port: int, source: str, action: str) -> None:
        self.firewall_rules.append({"port": port, "source": source, "action": action})

@dataclass
class VM:
    name: str
    Host: str
    Type: str
    network: NetworkConfig | None = None
    role: str = "Unassigned"
    network_segment: str = "Unknown"

    def attach_network(self, network_config: NetworkConfig) -> None:
        self.network = network_config
