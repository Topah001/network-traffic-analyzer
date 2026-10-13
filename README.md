# 47 — Network Traffic Analyzer

An **offline-only** analyzer for PCAP/PCAPNG files that you supply. It reports protocol counts, endpoint packet counts, bidirectional connection summaries, and configurable header-based patterns (destination-port fanout and watched destination ports). It does not sniff live traffic, intercept connections, extract credentials, dump packet payloads, evade detection, or exploit systems.

## Install and run

Requires Python 3.10+. Core code uses Scapy for offline capture parsing. Install with `python -m pip install -r requirements.txt`, or `python -m pip install '.[pcap]'` from this folder. If Scapy is unavailable, the API gives explicit installation guidance. Run tests with `python -m unittest discover -s tests -v`.

```python
from traffic_analyzer import AnalysisConfig, analyze_capture
report = analyze_capture("authorized-capture.pcap", AnalysisConfig(port_scan_threshold=8))
```

Analyze only captures you are authorized to inspect. Captures may contain sensitive personal or organizational metadata even when only summaries are displayed; protect files and reports, minimize retention, and do not publish private captures. Pattern matches are heuristic indicators, not proof of malicious activity.
