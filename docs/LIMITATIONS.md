# Limitations

- PCAP-NG is not supported. Classic PCAP link type 1, Ethernet, is the decoded path.
- VLAN tags, IPv6, IP reassembly, TCP options, TCP stream reassembly, and checksum verification are not implemented.
- DNS uses UDP without EDNS or TCP fallback. Only common answer data receives friendly formatting.
- PE parsing stops after core headers and the section table. Declared nonempty raw section data must be wholly present; malformed or truncated ranges produce a controlled parse error. Imports, exports, resources, signatures, and relocations are not parsed.
- ELF parsing currently reports the main header and table metadata, not individual program or section entries.
- Log parsing covers a few documented input shapes. Unknown records are retained rather than guessed.
- Correlations are educational rules without tuning, enrichment, or persistence.
- Process and socket visibility depends on OS permissions and races with process exit.
- Windows creation time and Unix inode-change time both appear under the portable `created` label, although their filesystem semantics differ.
- Windows route inspection depends on `Find-NetRoute` or the numeric rows in `route print -4`. Restricted sessions can deny both mechanisms. Linux returns the selected host route as `/32`, not the original table prefix.
- DNS queries require outbound UDP/53 access. Failures are reported cleanly.

