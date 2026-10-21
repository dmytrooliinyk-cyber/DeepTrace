# Network parsing

Multibyte fields in Ethernet, IP, and transport headers use network byte order, which is big-endian. `struct` formats therefore begin with `!`. MAC and IP addresses are formatted only after the parser has validated the containing header.

## Ethernet and ARP

An Ethernet II header has two six-byte addresses and a two-byte EtherType. DeepTrace recognizes `0x0800` as IPv4 and `0x0806` as ARP. ARP decoding is restricted to Ethernet hardware addresses and IPv4 protocol addresses, the common 28-byte form.

## IPv4

The upper nibble of the first byte is the version. The lower nibble is IHL, measured in 32-bit words, so an IHL of 5 means 20 bytes. The flags and fragment offset share one 16-bit field. A nonzero fragment offset suppresses transport parsing because the bytes may begin in the middle of a segment.

DeepTrace displays the checksum field but does not currently verify the checksum. Total length bounds the payload when the capture includes trailing data. A truncated captured payload remains bounded by the bytes actually present.

## Transport protocols

TCP data offset is another word count. The low flag bits expose FIN, SYN, RST, PSH, ACK, and URG. UDP's length includes its eight-byte header. ICMP decoding covers its common header and echo request/reply identifier and sequence fields.

Five-tuples preserve packet direction. This makes the observed client-to-server and server-to-client counts explicit. A small state tracker recognizes SYN, SYN/ACK, ACK; it does not retransmit, reassemble streams, or infer application sessions.

Classic PCAP global headers use a signed 32-bit timezone correction followed by unsigned 32-bit sigfigs, snap length, and link type fields. The magic bytes select both byte order and microsecond or nanosecond timestamp resolution.

## DNS

DNS names are length-prefixed labels. In a response, the top two bits `11` indicate a compression pointer and the remaining 14 bits are an offset from the beginning of the message. The decoder tracks visited offsets to reject cycles. Queries are assembled manually, sent through a UDP socket, and matched to responses by transaction ID.

