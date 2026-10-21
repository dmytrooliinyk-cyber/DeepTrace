# Architecture

DeepTrace has four paths through a small shared core.

```text
CLI -> validation -> parser or inspector -> dataclass / normalized model -> output

PCAP -> global header -> packet records -> Ethernet -> IPv4 -> TCP / UDP / ICMP
                                                \-> ARP
                                      -> directional five-tuple flows

file -> signatures + hash + entropy -> PE or ELF -> header and section details

logs -> source parser -> normalized Event -> timestamp order -> correlations
```

`deeptrace.cli` is intentionally procedural. Command dispatch is easier to audit here than a plugin framework would be. Expected failures use `DeepTraceError` or `ParseError`, and the CLI converts them into one-line errors with exit status 2.

`deeptrace.binary` is the shared trust boundary for byte ranges. Parsers check that a complete structure exists before unpacking it. Nested parsers return dataclasses, which keep protocol facts separate from presentation. The JSON serializer understands dataclasses, dates, paths, and enums.

System inspection differs because its inputs are live and permission-dependent. It returns dictionaries containing available values and explicit notes for unavailable native details. It performs no configuration changes.

