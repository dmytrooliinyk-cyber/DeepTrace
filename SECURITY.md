# Security policy

DeepTrace is an educational, defensive inspection tool. It parses user-supplied binary data and reads local system metadata. It does not inject packets, scan networks, exploit services, collect credentials, or install persistence.

## Reporting a problem

Please use GitHub's private vulnerability reporting feature if it is enabled for this repository. Otherwise, open an issue that describes the affected command and a minimal safe input. Do not attach malware, credentials, private packet captures, or personal logs.

## Operational guidance

Treat packet captures and logs as potentially sensitive. Work with copies, use only data you are authorized to inspect, and avoid publishing files that contain private addresses, account names, or authentication material. Parsers enforce bounds checks, but untrusted input should still be handled in a restricted environment.

MD5 output is provided only as a commonly used identification hash. It is not presented as collision-resistant or suitable for security decisions.

