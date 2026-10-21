# Testing

The test suite uses pytest and deterministic synthetic bytes. It covers endian helpers, bit extraction, entropy endpoints, Ethernet, IPv4, TCP flags, UDP, ARP, truncation, fragments, PCAP byte orders and field types, flow keys, DNS labels and pointers, CIDR arithmetic, Windows route selection, file signatures, PE section ranges, ELF, per-field process failures, UTC normalization, sorting, and contextual correlation.

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
python -m deeptrace route 8.8.8.8
```

DNS and route commands depend on network and operating-system state. Unit tests therefore exercise their pure parsing and calculation layers with deterministic fixtures, while live route checks are run when the host supports them.

