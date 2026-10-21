# System internals

Host inspection uses psutil to enumerate network interfaces, listening sockets, CPU count, and memory statistics. A listener is a TCP socket in LISTEN state or a bound UDP socket. Results can vary between runs because processes and sockets are live state.

Process inspection groups related psutil calls under `oneshot()` to reduce repeated system queries. It reports identity, parent, executable, command line, user, start time, direct children, and accessible Internet sockets.

On Linux, `/proc/<pid>/status` exposes selected process state as text. `/proc/<pid>/fd` contains symbolic links for open descriptors, including files and sockets. Access can fail when ownership, ptrace restrictions, or process exit races intervene. DeepTrace records that detail as unavailable.

On Windows, process details come from psutil's wrappers around supported Windows APIs. No administrator rights are assumed. The route command reads `route print -4`; Linux uses `ip -4 route get`. Neither path changes the routing table.

