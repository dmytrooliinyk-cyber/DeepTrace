# Contributing

Contributions should keep DeepTrace small, readable, and educational. A parser should expose the underlying layout rather than hide it behind a large dependency.

1. Create a focused branch.
2. Add or update deterministic tests.
3. Run `python -m pytest`.
4. Run the CLI command affected by the change.
5. Update the relevant document when behavior or limitations change.

Use Python 3.12 or newer. Prefer the standard library. New runtime dependencies need a clear technical reason. Do not add active scanning, exploitation, packet injection, credential handling, or malware samples.

Bug reports are most useful when they include the command, platform, expected result, actual result, and a small sanitized input.

