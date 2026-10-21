# DeepTrace

DeepTrace is a small Python CLI for inspecting packets, files, processes, networks, and security events below their usual abstractions. It exists to answer a practical question: what do common security tools actually read and calculate before they draw a graph or raise an alert?

The implementation favors direct parsing with `struct`, byte slices, bit masks, and standard operating-system interfaces. It does not use Scapy, pefile, pyelftools, a web framework, or a dashboard.

## What it demonstrates

- byte order, safe bounds checks, bit fields, hexadecimal data, and entropy
- Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, PCAP records, ports, and flows
- CIDR arithmetic and longest-prefix routing decisions
- local processes, child processes, sockets, interfaces, and selected native OS details
- magic-byte detection, hashes, PE sections, ELF headers, and memory permissions
- log normalization, UTC timestamps, timelines, and deterministic correlations

See [docs/FEATURE_MAP.md](docs/FEATURE_MAP.md) for the feature-to-concept mapping.

## Install

```console
git clone https://github.com/GGtascher/DeepTrace.git
cd DeepTrace
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
```

On Linux or macOS, activate with `source .venv/bin/activate`.

## Quick start

```console
python -m deeptrace --help
python -m deeptrace subnet 192.168.10.73/27
python -m deeptrace pcap sample-data/sample.pcap
python -m deeptrace explain ipv4 sample-data/sample.pcap
python -m deeptrace file README.md
python -m deeptrace timeline sample-data/events.jsonl
python -m deeptrace host
python -m deeptrace process 1234
python -m deeptrace dns example.com
python -m deeptrace route 8.8.8.8
```

Most structured reports are JSON. `pcap`, `timeline`, and `subnet` default to compact terminal output and accept the global `--json` option before the command.

## Example output

```text
$ python -m deeptrace pcap sample-data/sample.pcap
PCAP 2.4, link type 1, snaplen 65535
  1  12:00:00.120  192.0.2.10:51532 -> 198.51.100.20:443 TCP SYN
  2  12:00:01.121  198.51.100.20:443 -> 192.0.2.10:51532 TCP ACK/SYN
  3  12:00:02.122  192.0.2.10:51532 -> 198.51.100.20:443 TCP ACK

Flows
192.0.2.10:51532 -> 198.51.100.20:443 TCP  packets=2
198.51.100.20:443 -> 192.0.2.10:51532 TCP  packets=1

TCP handshake observations
192.0.2.10:51532 -> 198.51.100.20:443  handshake observed
```

```text
$ python -m deeptrace explain ipv4 sample-data/sample.pcap
First byte: 0x45
Binary: 01000101
Version: 0100 = 4
IHL: 0101 = 5
Header length: 5 x 4 = 20 bytes
...
TCP flags: 0x02
Binary: 00000010
SYN = 1
Meaning: SYN
```

## How the parts fit

The CLI validates arguments and sends each input to one focused inspector. Binary parsers return dataclasses. The output layer converts those models to JSON or small readable summaries.

```text
PCAP -> record header -> Ethernet -> IPv4 -> TCP / UDP / ICMP -> flow summary
file -> magic and hashes -> PE / ELF parser -> sections and indicators
logs -> normalization -> ordered events -> deterministic correlation findings
```

Packet parsing starts from raw captured bytes. The IPv4 parser splits the first byte into version and IHL, uses IHL to locate the payload, then selects a transport parser by protocol number. Non-initial fragments are left undecoded because they do not contain a complete transport header. Unknown EtherTypes and IP protocols remain visible without causing a crash.

The PCAP reader supports classic PCAP with microsecond or nanosecond timestamps and Ethernet link type. It does not support PCAP-NG or TCP stream reassembly. The flow view intentionally keeps direction, so request and reply directions are separate five-tuples.

DNS queries are assembled as bytes and sent over UDP. Responses are parsed by DeepTrace, including bounded compression-pointer traversal and A, AAAA, CNAME, MX, and TXT answer rendering. The active query defaults to Google's public resolver but can target another explicitly supplied resolver with `--server`.

## Files and executables

The file command detects PE, ELF, PDF, ZIP, PNG, and JPEG from signatures, not extensions. It calculates SHA-256, an identification-only MD5, Shannon entropy, and filesystem timestamps.

For PE files, DeepTrace follows `e_lfanew` from the DOS header to the COFF and optional headers, then walks section entries. Declared raw section ranges must fit within the file before entropy is calculated. Writable and executable sections, high entropy, and unusual names are shown only as informational indicators. None of them proves malicious intent. ELF inspection reads class, endianness, ABI, machine, entry point, and program/section table metadata directly from the ELF header.

## Host and process inspection

`host` uses psutil for portable interfaces, listeners, CPU, and memory information. On Linux, `process` also reads selected values from `/proc/<pid>/status` and counts accessible file descriptors. On Windows, psutil obtains process and connection information through supported OS APIs. Permission failures are reported on the affected field instead of aborting unrelated process details.

Routing inspection is read-only. Windows first asks `Find-NetRoute` for the selected route and falls back to evaluating the full `route print -4` table by prefix length and metric. Linux uses `ip route get`, whose result is the kernel's selected route rather than a reconstructed full table.

## Logs, timeline, and correlation

The normalizer understands JSONL events with common Sysmon-like fields, Linux SSH authentication lines, and basic syslog. Timezone-aware inputs are converted to UTC, while naive ISO timestamps are interpreted as UTC. Unknown input is retained in `raw_event`. This is a deliberately small teaching parser, not a universal log ingestion system.

The correlation engine contains three understandable patterns: repeated SSH failures, a PowerShell/network/temp-executable execution chain, and a standalone executable written to a temporary directory. The execution chain uses chronological order, a five-minute window, host context, available process identity, and the created executable basename. Findings are deterministic and preserve event indexes. They are examples of how higher-level security observations can emerge from normalized facts.

## Repository structure

```text
deeptrace/           CLI and implementation modules
tests/               deterministic parser and correlation tests
sample-data/         safe synthetic capture, events, auth log, malformed bytes
docs/                focused technical notes and design decisions
tools/               deterministic sample-data generator
.github/workflows/   Python 3.12 test workflow
```

## Security scope and limitations

DeepTrace is passive, local, or offline except for an explicitly requested DNS lookup. It does not scan hosts, inject packets, alter routes, exploit services, or execute inspected files. All bundled addresses come from documentation ranges.

Important limitations include classic PCAP only, Ethernet only, IPv4 only, no IP reassembly, no TCP stream reassembly, a narrow set of DNS record renderers, header-level PE/ELF inspection, and OS-dependent access to process and route metadata. More detail is in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Testing

```console
python -m pytest
```

The tests construct synthetic packets, captures, executable headers, DNS compression examples, and event sequences. No network access or elevated permissions are required.

## Roadmap

Possible focused additions are VLAN header parsing, IPv6, PCAP-NG section headers, PE data-directory summaries, ELF program-header inspection, and more explicit route-table adapters. Each addition should remain small enough that a reader can follow the bytes to the result.

## License

MIT. Copyright (c) 2026 Dmytro Oliinyk.

