# OS/SG collected contract receipt

Hermes source pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.
Atoms base: `744e2b7dbf8f44fea0f2d24433c5e29df523d7d5`.

The executable OS/SG contracts are now owned by the atoms roof and collected
by its default pytest configuration:

| ID | Collected node | Source design |
|---|---|---|
| `T-OS-01` | `tests/test_os_xfail.py::test_t_os_01_pin_mismatch_denies_or_escalates` | `capability-gate/design/os` |
| `T-SG-04` | `tests/test_sg_xfail.py::test_t_sg_04_sensitive_write_escalates` | `capability-gate/design/sg` |

Both contracts are `xfail(strict=True)`. An implementation that makes either
contract pass must remove its marker and add the matching evidence receipt in
the same change; an unexplained xpass fails collection.

`T-OS-02a..d` is not represented as four empty tests. The source design names
provenance/taint on tool results but does not define the four executable
fixtures or assertions. Inventing those definitions here would turn a
visibility contract into an unfalsifiable placeholder.

The remaining design IDs also need executable fixture definitions before they
can make falsifiable assertions. No paid calls, live MCP systems, judge
application, AgentDojo, or aegisbox runs are part of this port.

Dirty-tree disclosure: pre-existing untracked Track A judge receipts and raw
compare outputs were present when this branch was cut. They were not read into,
modified by, or staged with this Track B change.
