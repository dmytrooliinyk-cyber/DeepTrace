# Logs and correlation

Normalization gives unlike source records a shared vocabulary: timestamp, source, event type, host, user, addresses, process, PID, path, message, and raw event. The original record is retained so a reviewer can recover context that the common fields omit.

JSONL parsing recognizes explicit DeepTrace fields and a small subset of Sysmon-style names such as `EventID`, `UtcTime`, `Image`, `DestinationIp`, and `TargetFilename`. Event IDs 1, 3, and 11 map to process start, network connection, and file creation. Text parsing recognizes common SSH authentication and syslog shapes.

Events are sorted by timezone-aware timestamps. Missing or invalid timestamps sort at the Unix epoch rather than being silently assigned the current time.

Correlations are plain deterministic functions. Repeated failures are grouped by source address and username. The execution-chain example searches a short forward window for PowerShell, a network connection, creation of an executable below a temporary directory, and launch of the same basename. A separate low-risk observation covers temporary executables not already part of that chain.

These rules teach event relationships. They do not include asset criticality, allowlists, baselines, suppression, enrichment, or a complete detection language.

