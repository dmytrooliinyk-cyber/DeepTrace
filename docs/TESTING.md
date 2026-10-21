# Testing

The test suite uses pytest and deterministic synthetic bytes. It covers endian helpers, bit extraction, entropy endpoints, Ethernet, IPv4, TCP flags, UDP, ARP, truncation, fragments, PCAP metadata, flow keys, DNS labels and pointers, CIDR arithmetic, file signatures, PE, ELF, log normalization, sorting, and correlation.

Run all tests from the repository root:

```console
python -m pip install -e ".[dev]"
python -m pytest
```

Representative manual checks:

```console
python -m deeptrace --help
python -m deeptrace subnet 192.168.1.73/27
python -m deeptrace file README.md
python -m deeptrace pcap sample-data/sample.pcap
python -m deeptrace explain ipv4 sample-data/sample.pcap
python -m deeptrace timeline sample-data/events.jsonl
python -m deeptrace timeline sample-data/linux-auth.log
python -m deeptrace host
```

DNS and route commands depend on network and operating-system state, so unit tests exercise their pure parsing and calculation layers instead of external services.

