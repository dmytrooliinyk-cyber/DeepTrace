# Design decisions

## One module per coherent concern

Network protocols share `network.py` because their dataclasses and dispatch logic are tightly related. PE and ELF share `executables.py`. This avoids a directory of tiny files while keeping live system inspection, DNS, PCAP, routing, and events independent.

## Direct parsers

Scapy, pefile, and pyelftools would hide the byte layouts the project intends to demonstrate. Direct `struct` parsing keeps offsets, word sizes, flags, and endianness visible. psutil is retained where portable process APIs are the subject rather than a binary format.

## Dataclasses at parser boundaries

Parsers return typed values rather than formatted strings. This makes tests precise and lets JSON output reuse the same facts as terminal summaries.

## Narrow error handling

Malformed user data becomes `ParseError`. Platform limitations and input problems become `DeepTraceError`. Unexpected programming errors are not swallowed, which keeps defects visible during development.

## Passive scope

The only outbound operation is a DNS query to an explicitly selected resolver. Capture analysis is offline, routes are read-only, inspected executables are never loaded, and process inspection does not alter target processes.

