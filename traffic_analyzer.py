"""Offline-only summaries for user-supplied PCAP/PCAPNG files.

This module has no packet-capture, sniffing, interception, or payload-output path.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AnalysisConfig:
    port_scan_threshold: int = 10
    watched_destination_ports: frozenset[int] = field(default_factory=frozenset)

    def __post_init__(self):
        if self.port_scan_threshold < 1:
            raise ValueError("port_scan_threshold must be positive")
        if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in self.watched_destination_ports):
            raise ValueError("watched ports must be between 1 and 65535")


def _endpoint(address: str, port: int | None) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"{host}:{port}" if port is not None else host


def analyze_packets(packets, config: AnalysisConfig | None = None) -> dict:
    """Summarize headers and counters from already supplied packet objects."""
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
    except ImportError as exc:
        raise RuntimeError("Scapy is required; install it with: python -m pip install '.[pcap]'") from exc

    config = config or AnalysisConfig()
    protocols = Counter()
    endpoints = Counter()
    flows = {}
    source_ports = defaultdict(set)
    alerts = []
    packet_count = 0

    for packet in packets:
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network is None:
            continue
        source, destination = network.src, network.dst
        if packet.haslayer(TCP):
            transport, source_port, destination_port = "TCP", int(packet[TCP].sport), int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            transport, source_port, destination_port = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            transport, source_port, destination_port = "ICMP", None, None
        else:
            transport, source_port, destination_port = "OTHER", None, None
        packet_count += 1
        protocols[transport] += 1
        source_endpoint = _endpoint(source, source_port)
        destination_endpoint = _endpoint(destination, destination_port)
        endpoints[source_endpoint] += 1
        endpoints[destination_endpoint] += 1

        if source_port is not None:
            source_ports[source].add(destination_port)
        if destination_port in config.watched_destination_ports:
            alerts.append({"pattern": "watched_destination_port", "source": source, "destination": destination, "port": destination_port})

        ordered = tuple(sorted((source_endpoint, destination_endpoint)))
        key = (transport, *ordered)
        if key not in flows:
            flows[key] = {"protocol": transport, "endpoint_a": ordered[0], "endpoint_b": ordered[1], "packets": 0}
        flows[key]["packets"] += 1

    for source, ports in sorted(source_ports.items()):
        if len(ports) > config.port_scan_threshold:
            alerts.append({"pattern": "destination_port_fanout", "source": source, "distinct_ports": len(ports), "threshold": config.port_scan_threshold})

    return {
        "packet_count": packet_count,
        "protocols": dict(sorted(protocols.items())),
        "endpoints": [
            {"endpoint": endpoint, "packets": count}
            for endpoint, count in sorted(endpoints.items(), key=lambda row: (-row[1], row[0]))
        ],
        "connections": [flows[key] for key in sorted(flows)],
        "alerts": alerts,
    }


def analyze_capture(path: str | Path, config: AnalysisConfig | None = None) -> dict:
    """Read and summarize an authorized offline capture; never capture live traffic."""
    capture = Path(path)
    if capture.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("Only user-supplied .pcap and .pcapng files are supported")
    if not capture.is_file():
        raise FileNotFoundError(capture)
    try:
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise RuntimeError("Scapy is required; install it with: python -m pip install '.[pcap]'") from exc
    with PcapReader(str(capture)) as reader:
        return analyze_packets(reader, config)
