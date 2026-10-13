import unittest
from pathlib import Path
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap
from traffic_analyzer import AnalysisConfig, analyze_capture, analyze_packets


class TrafficAnalyzerTests(unittest.TestCase):
    def samples(self):
        return [
            IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=50000, dport=80),
            IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=50001, dport=443),
            IP(src="192.0.2.10", dst="198.51.100.30") / UDP(sport=50002, dport=53),
            IP(src="203.0.113.7", dst="198.51.100.20") / TCP(sport=50003, dport=23),
        ]

    def test_constructed_packets_summary_and_configurable_patterns(self):
        report = analyze_packets(
            self.samples(),
            AnalysisConfig(port_scan_threshold=2, watched_destination_ports=frozenset({23})),
        )
        self.assertEqual(report["packet_count"], 4)
        self.assertEqual(report["protocols"], {"TCP": 3, "UDP": 1})
        self.assertEqual(len(report["connections"]), 4)
        names = {alert["pattern"] for alert in report["alerts"]}
        self.assertEqual(names, {"destination_port_fanout", "watched_destination_port"})
        self.assertTrue(all("payload" not in str(item).lower() for item in report["connections"]))

    def test_reads_user_supplied_offline_pcap(self):
        path = Path(__file__).parent / "authorized-sample.pcap"
        try:
            wrpcap(str(path), self.samples())
            result = analyze_capture(path)
            self.assertEqual(result["packet_count"], 4)
        finally:
            path.unlink(missing_ok=True)

    def test_rejects_unsupported_file_type(self):
        with self.assertRaises(ValueError):
            analyze_capture(Path(__file__).parent / "capture.txt")


if __name__ == "__main__":
    unittest.main()
