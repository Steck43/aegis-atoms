# OS/SG collected contract receipt

Hermes source pin: `ccd8deaa6705bd6ca1890584d8f4055fe61227b5`.
Atoms base: `5e92ae10ab81ffa6c13fb95e56ca35ed9f98e236`.

The executable OS/SG contracts are now owned by the atoms roof and collected
by its default pytest configuration:

| ID | Collected node | Source design |
|---|---|---|
| `T-OS-01` | `tests/test_os_xfail.py::test_t_os_01_pin_mismatch_denies_or_escalates` | `capability-gate/design/os` |
| `T-SG-04` | `tests/test_sg_xfail.py::test_t_sg_04_sensitive_write_escalates` | `capability-gate/design/sg` |

Both contracts are `xfail(strict=True)`. An implementation that makes either
contract pass must remove its marker and add the matching evidence receipt in
the same change; an unexplained xpass fails collection.

The remaining design IDs are not represented as empty tests:

- `T-OS-02a..d`, `T-OS-03`, `T-OS-04`, `T-OS-05`, and OS-6 need executable
  fixture definitions before they can make a falsifiable assertion.
- `T-SG-01`, `T-SG-02`, `T-SG-03`, and `T-SG-05a..c` need mutation, hold-out,
  behavior-lint, and signal fixtures.

No paid calls, live MCP systems, judge application, or AgentDojo runs are part
of this port.
