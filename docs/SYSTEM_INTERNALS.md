# System internals

Host inspection uses psutil to enumerate network interfaces, listening sockets, CPU count, and memory statistics. A listener is a TCP socket in LISTEN state or a bound UDP socket. Results can vary between runs because processes and sockets are live state.

Process inspection groups related psutil calls under `oneshot()` to reduce repeated system queries. It reports identity, parent, executable, command line, user, start time, direct children, and accessible Internet sockets. Access failures are handled beside the individual psutil call, so one denied field does not normally discard the rest of the report. If the target process disappears, the command still returns a clean process-not-found error.

On Linux, `/proc/<pid>/status` exposes selected process state as text. `/proc/<pid>/fd` contains symbolic links for open descriptors, including files and sockets. Access can fail when ownership, ptrace restrictions, or process exit races intervene. DeepTrace records that detail as unavailable.

On Windows, process details come from psutil's wrappers around supported Windows APIs. No administrator rights are assumed. The route command prefers the read-only `Find-NetRoute` cmdlet, with the full `route print -4` table as a fallback. The fallback identifies numeric route rows without depending on English headings, then applies longest-prefix and metric selection. Linux uses `ip -4 route get`. Neither path changes the routing table.

