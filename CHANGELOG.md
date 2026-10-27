# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Every tool call now carries a coverage result. A call is COVERED when a path, shell, or memory family bounded it or an atom fired, and only a COVERED call runs in enforce. Any other call takes the effect of `control.coverage_unknown` from the catalog (default human review, never weaker), gets no box ticket, and the hook writes one coverage line per call to the firings log, including calls where nothing fired and calls the evaluator could not finish. A gate grant does not count as coverage. A malformed `coverage_unknown` block falls back to hold in enforce. `tests/test_coverage_unknown.py`, `tests/test_coverage_unknown_hardening.py`.
- C2 shell structure: a plain `command` string is split into tokens and held to the same per-binary argv allowlist as an `argv` list, so the binary and every flag must be listed in either form. A string that does not split is denied. `tests/test_shell_string_argv_parity.py`.
- Trusted kit-local-manifest re-pin to kit global hooks path (`merge_gate.py` at `97fc05767615`).
- Removed a third-party name from a catalog confidentiality marker. The bound-prove script path comes from the environment, and a human-review hold says it requires operator approval. `tests/test_public_surface_names.py` fails if the retired seat name is in the tree or the marker list is no longer the generic labels.
- Public path scrub: the judge scripts no longer compile in a home path or key file. The provider key comes from `ANTHROPIC_API_KEY` or a file named by `ANTHROPIC_ENV_FILE`, and an unset or missing file refuses. `tools/build_registry.py` reads the vault catalog from `--vault-catalog` or `AEGIS_VAULT_CATALOG` and refuses a path that is not a file. `tests/test_public_paths.py` scans every tracked file and fails on a home path (including a JSON-escaped Windows one), an env-file path, or a dotted IPv4 address.
- Fixed mis-encoded dashes and arrows in `__init__.py` docstrings and this changelog; they are plain ASCII now.
- `tests/test_public_surface_names.py` no longer passes on an absent or short leak denylist: CI fails unless the `LEAK_DENYLIST` secret has the seat row, and other hosts skip with the reason. The local list is found through the git common dir, so a linked worktree reads it too. A planted-name test proves the scan reports a hit, and the bound-prove refusal is checked by calling the plugin with the variable unset. The floor `pytest` step passes the secret in.
- `tests/test_public_surface_names.py` picks the seat row by its SHA-256, not its position, so a row added ahead of it cannot move the scan to another name. A tracked file that is not UTF-8 now counts as a hit instead of being skipped, with UTF-16 and cp1252 plants as tests. A test pins that a missing list or seat row fails under CI and skips elsewhere.
- Raise `zizmorcore/zizmor-action` from 0.6.2 to 0.6.4 (`cc914d7f...`), recreating closed Dependabot #28 on a fresh branch.
- Ruff development and CI range resolves to `>=0.16.9,<0.17`, replacing the closed Dependabot proposal with a branch that runs the protected floor. Receipt: `RUFF-0.16.9-2026-10-11.md`.

### Added

- GIT-5 strip-check CI fixture: `tools/strip_ci_fixture` wrong-answer strip proves red, head proves green; workflow `strip-check.yml` and `.floor/strip.tsv`.

- Default pytest collection now carries `T-OS-01` and `T-SG-04` as strict expected failures, so implementing either contract without removing its marker and landing evidence fails the suite. `T-OS-02a..d` remains blocked on missing executable fixture definitions rather than being represented by empty tests. Receipt: `OS-SG-XFAIL-SUITE-2026-10-11.md`.
- JUDGE-COMPARE scripted-call shadow runner (`scripts/run_judge_compare_pilot.py`) with track consult policy (`judge_compare_policy.py`): only `attack` and `ambiguous` tracks force-consult the judge. Receipt `JUDGE-COMPARE-PRE-G6-REGRADE-2026-10-10.md`.
- Part 0 judge wiring: Hermes `pre_tool_call` runs gate -> atoms -> box (when invoked) -> judge -> human. `engine.apply_judge_phase` owns the deferred judge; live mount passes `judge_enabled=False` into evaluate then applies after bound prove. Phase wall-clock `JUDGE_PHASE_DEADLINE_S` (10s) with pool `shutdown(wait=False, cancel_futures=True)`, Anthropic `max_retries=0`, and a `judge_started` G6 row before the call. Per-call apply re-check requires `AEGIS_JUDGE_APPLY_GO=1`, `AEGIS_PROFILE_ID=step11-test`, and `$HERMES_HOME/.aegis/profile_id`. Cage escalation always reaches the door; G6 write failures fail closed; quota skips write `judge_skipped`. Engine default `judge_apply_verdict` stays False. Receipts: `JUDGE-INVENTORY-2026-10-10.md`, `JUDGE-WIRING-2026-10-10.md`, `FIXFIRST-RESPONSE-2026-10-10.md`.

### Fixed
- `strip_check.sh` runs every recipe row, including a last row with no newline, and keeps strip stdin from eating later rows.

- GIT-5 strip-check: recipe rows name their strip target; empty `.floor/strip.tsv` fails; restore-on-exit so a failed strip cannot leave the tree stripped.
- GIT-5 strip-check: run the fixture under an isolated pytest.ini (`--noconftest`, empty `pythonpath`) so the job that installs only pytest never imports the plugin root / PyYAML.
- GIT-5 strip-check: pin `actions/setup-python` to the floor digest, strip UTF-8 BOM from the fixture, load `add.py` via importlib so CI does not pull the plugin root.
- The bound prove step (`AEGISBOX_PROVE=1`) no longer falls back to a script path on one developer machine. With `AEGISBOX_BOUND_PROVE` unset it refuses with exit 2 and runs nothing; enforce mode blocks the call. `tests/test_bound_prove_script_path.py`.
- README no longer says the live atoms profile is enforce or that the judge subtracts on the live mount. Those lines read a config mode string and the engine path; no receipt shows this plugin loaded into the Hermes gateway on the live profile, or a judge subtract there. The badge now says the config sets enforce and the live load is not measured. Older entries below that say "live profile", "live mount arms" or "live Sonnet cycle audits" describe config and test paths, not a measured live load.
- Compare runner no longer hardcodes `judge_force_consult=True` on every pilot row (that produced 500/500 `flag_for_review`). Normal and honest_mistake abstain; attack and ambiguous consult. `tests/test_judge_compare_consult_policy.py`. `verify_derived.sh` now prints the `gen_manifest.sh` remediation when `SHA256SUMS` lags.
- Abandoned judge threads after a phase deadline no longer append cage audit rows into a later call's G6 file. Each phase binds its own audit path and cancel flag; cancelled workers skip G6 audit writes only. Completed provider calls are still metered, cancel is checked before each API call and retry, and a cancelled phase starts no new re-ask (`tests/test_judge_abandoned_thread.py`).
- When a provider call completes and the phase cancel fires, write a per-call `judge_cost` G6 row with `cancelled: true` and the metered `judge_cost_usd` so spend rows reconcile under the $50 cap (`test_cancelled_phase_writes_cost_row_with_marker`).
- `evaluate_tool_call` defaults `judge_apply_verdict` to False (was True). Omitting the kwarg no longer applies the judge. `register` refuses a True mount config without `AEGIS_JUDGE_APPLY_GO=1`. Apply-path fuzzer still passes True explicitly. Receipts: `JUDGE-APPLY-DEFAULT-2026-10-09.md`, `JUDGE-CALL-SITES-2026-10-09.md`.
- `evaluate_tool_call` fails closed on any `gate_decision` that is not a canonical allow (exact string `"allow"` after `Enum.value`). ASK escalates to `human_review`; DENY, THROWN, malformed, missing, wrong-type, and plain-dict verdicts block. Previously only the literal deny string blocked and every other shape fell through. `engine.classify_gate_verdict` owns the map; `tests/test_t_comp_01_verdict_matrix.py` and `receipts/raw/t-comp-01-expected-matrix.json` pin the full shape set (T-COMP-01 / ATOMS-FAILCLOSED).

### Added

- Step 11 bound-prove results now return parsed JSON evidence to the shared Hermes call context. The context records the atoms profile mode, both Hermes-side digests, prove exit code, and exact prove object; enforce still blocks when prove fails, while observe records the failure without earning a live-evidence stamp.
- evaluate_tool_call records decision_digest from the gate decision it read and issues a unique box_ticket when the call is not blocked.

### Added

- `evaluate_tool_call` takes `gate_decision`. A gate deny blocks in atoms; a gate allow never clears an atoms block. `tests/test_gate_decision_param.py` pins both sides.

### Fixed
- `strip_check.sh` runs every recipe row, including a last row with no newline, and keeps strip stdin from eating later rows.

- C2 argv lists use a per-binary flag allowlist instead of joining tokens and scanning for shell punctuation. Joining missed `tar --checkpoint-action`, `ssh -oProxyCommand`, and nested interpreters (`bash -c`, `python -c`, `sh -c`). The binary must be a bare basename on the map; a path-form binary (`/tmp/evil`, `./tool`) denies. Every flag token must be listed for that binary. Shell punctuation inside a token still denies. `tests/test_argv_flag_allowlist.py` pins the deny and allow cases.
- C2 unsanitized-shell checks a command string against an allowlist, not a list of known shell constructs. The old list missed a trailing `&`, a newline, an env prefix (`FOO=bar cmd`), brace expansion and heredocs, so `sleep 1 &` passed under enforce. A command string now passes only when every character is a letter, digit, space, one of `_ . / : , @ % + = -`, or sits in a quoted run of those same characters. The first token may not be `NAME=VALUE`. Anything else fires. `tests/test_shell_closed_world.py` walks every punctuation character outside the plain set, so widening the old list could not have passed it. `catalog/REGISTRY.tsv` line numbers moved by one.
- `AuditStore.append` now hash-chains each JSONL line (`prev_hash` / `this_hash`). Rewriting an older line fails `verify`. The previous append-only test only counted lines, so a rewrite stayed green.
- Catalog rank update uses the full `EFFECT_RANK` lattice with `>=`. An enforce monitor now wins when nothing stronger fired; the older `(block, human_review)` guard already kept a later monitor from clearing a block. A weaker hold cannot outrank a block. Content detection still refuses to write `human_review` over an earlier action-gating block.
- Published `task_scope_enabled` stays false on the plugin entry, the engine signature, and a missing config key. A recorded flip to true left the A4 mount-flag tests green.
- Cage `_validate_opinion` re-boxes twin-module `JudgeOpinion` (plugin dir on `sys.path` plus package load) so live Sonnet cycle audits no longer pair with `slot_error:TypeError: slot must return JudgeOpinion`. Observe mount and Sonnet/budget modules prefer package-relative imports for `judge_audit` / `judge_budget` / `judge_slot_sonnet` so oneshot package load and the cage share one class identity. `tests/test_bounded_judge.py` pins the dual-import path.
- Retract the production SUPPORTS edge on `CTRL_SHELL` (argv schema-valid). Argv shell grammar is CONTRADICTED/BLOCK again; organic CONFLICTING stays SYNTHETIC-probe only. Terminal checks inspect `command` whenever present so a clean `argv` cannot mask an unsafe string. CONFLICTING handoff subprocess gains a 5s timeout and skips under observe (`AEGIS_ATOMS_MODE`). Action-gating ESCALATE no longer overwrites an earlier BLOCK (`best_effect != "block"`).
- Restore Author line `Landen Stecker` after the LF-index normalizer truncated a trailing `r` (same class as the in-branch `lowe` miss).
- Pass `active_task_id` from the live mount only when the id is declared in `task_scopes.yaml`; unknown Hermes UUIDs no longer fail-closed the whole mount. Unknown ids inside `task_scope.py` also fall back to `default_local`.
- `_build_env` forwards `TERMINAL_CWD`/`PWD` so instruction/control/task-scope cwd and local prefixes can see the Hermes working directory. Local scope includes `${OBSIDIAN_VAULT_PATH}`.
- Collapse mode / judge / A4 flag reads into one `AtomsEntryConfig` snapshot with strict bool coerce (`"false"` stays false). Mount wiring test asserts the three flags and two YAML paths reach `evaluate_tool_call`.
- Restore `_is_backup_plugin_dirname` to compare against `lower` (a truncated `lowe` NameError blocked bak-path refusal under organic register).
- Load heartbeat defaults `gateway_pid` to the registering process PID when `HERMES_GATEWAY_PID` is unset, so dest proves are not left with `gateway_pid=unset` under a normal PluginManager mount.
- Organic package-load harness (`tests/test_organic_plugin_manager.py`) proves Hermes-style `hermes_plugins.aegis_atoms` registration blocks `rm -rf` and setup exceptions; bak siblings refuse register; heartbeat records `pid=` / `gateway_pid=`.
- `plugin.yaml` sets `require_mount: true` so an enabled-but-unmounted atoms tip refuses ungoverned tool traffic under Hermes mount verification.
- Enforce `pre_tool_call` fails closed on catalog miss and on any setup/evaluator exception, so Hermes hook swallow can no longer allow a destructive tool when the floor crashes. Package-relative sibling imports, register/install refusal of `.bak` tip shadows, widened `rm -r -f` / long-flag matching, and `tests/test_organic_fail_closed.py` pin the organic miss class.

### Changed

- Live mount can arm A4 instruction / task-scope / control-surface holds via `plugins.entries.aegis-atoms.*_enabled` (default off for strangers). Box CONFLICTING door is named by `AEGIS_CONFLICTING_HANDOFF` (dry only).
- README names the author profile so a stranger can click once from this roof to `github.com/Steck43`.

### Added

- Live mount arms `irreversible_ops_enabled=True` with the plugin's `irreversible_operations.yaml`. Declared deletes, `rm -rf`, and terraform destroy become holds under enforce. `tests/test_irreversible_mount.py` pins the flag and the hold path. Judge stays its own flag.
- C1 path-outside-root records `detector_kind=strangler-observe` when `AEGIS_STRANGLER_OBSERVE=1`. One deny. Shell stays on the legacy action-gating detector. The catalog is not grown.
- CONFLICTING rollup names the box door. `AEGIS_CONFLICTING_HANDOFF` points at `isolation-layer` `scripts/conflicting_handoff.py` and is invoked dry. Unset is `HANDOFF_UNWIRED`. The atoms seat never passes `--launch`. `always_invoked` stays false.
- Judge consult is its own flag. Plugin mode no longer turns the judge off. Live `judge_apply_verdict` is config (`plugins.entries.aegis-atoms.judge_apply_verdict`, default **false**): consult + `aegis-judge.jsonl` for tune; Landen GO flips apply. Sitting quota `AEGIS_JUDGE_SITTING_QUOTA` still caps paid consults. Shadow runs append `judge_apply_decision` rows (`applied`, `would_subtract`) and expose `judge_applied` / `judge_would_subtract` on `EvaluationResult`; `judge_subtracted` means the floor was mutated.
- Omit-flag test: `evaluate_tool_call` defaults `judge_apply_verdict` to True (engine harness). The live mount defaults False so shadow observations cannot mutate the floor until apply is armed. Config coerce for the apply flag is covered by `tests/test_judge_shadow_attestation.py`.
- CITATION.cff and `.zenodo.json` so a later tag can mint. No DOI on this record yet.
- `evidence/**/*.json` is marked `-text`, so receipts are stored as the bytes that were produced. Every other rule in `.gitattributes` normalises line endings on commit, which would rewrite a receipt after it was generated and leave any hash taken at generation time pointing at bytes the repository no longer holds.
- `.floor/derived.tsv` registers files that are a function of other files, and `.floor/craft/verify_derived.sh` regenerates each one and fails if the committed copy differs. `SHA256SUMS` is the first entry, generated by `scripts/gen_manifest.sh` from the git index. The `derived` workflow runs that check on every push, then runs `sha256sum -c` against a clean checkout. The estate's nightly readiness probe reads the same registry, so CI and the probe cannot disagree. README documents the verify command.
- J04 (CVE-2025-53967): executable substitution (`$(`, backtick, `<(`, `>(`) in a top-level string argument of a non-shell tool fires the unsanitized-shell atom. Content-bearing keys are exempt. `tests/test_j04_and_secret_globs.py` pins the scope limits as well as the hits.
- `atom.resource.read_hermes_secrets` also matches `**/.env`, `**/.env.*` and `**/secrets/**`. The atom stays observe.
- Population tests for the deny-overrides rollup (`tests/test_rollup_population.py`): generated populations of 1 to 500 atoms over many seeds, checked for order, duplicate, max, deny and monotone properties, each checker also run against a deliberately broken rollup. `tests/test_rollup_type_guarantee.py` adds the property-form gaps the triad tests left open, and `tests/test_lattice_consistency.py` pins the four hand-maintained maps between the engine's three-level lattice and `EffectRank`. A supporting firing lowering a contradicted BLOCK is recorded as a strict xfail (FIND 5).
- `tools/build_registry.py` writes `catalog/REGISTRY.tsv`, one row per atom id with the copies that carry it, and `--check` compares every reachable copy field by field.
- Catalog relaxations are keyed on who wrote the session text. `evaluate_tool_call` takes `session_origin` (`human`, `delegate`, `cron`, `webhook`, `unknown`; default `unknown`), and only `human` can relax. The plugin infers it in `pre_llm_call` from Hermes' `platform` and `sender_id` through `engine.session_origin_from_hook`: `subagent` is a delegate, `cron` is cron, webhook platforms and `webhook:` sender ids are webhook, CLI and TUI are human, a messaging platform is human only with a sender id, and anything else is unknown. On an enforce atom a downgrade to `monitor` is clamped to `human_review`, since the enforcing loop drops `monitor` and the atom would log a firing with no decision. A relaxation naming an unknown or stronger effect is ignored, and a bare-mapping `relaxations` loads as one entry. `tests/test_relaxation_provenance.py` covers every catalog atom across downgrade targets, origins and texts, through the engine and through the hook.
- Repo floor: GitHub Actions (secrets, authorship, tests 3.11/3.12, ruff, craft, zizmor/actionlint), Dependabot 7-day cooldown, SECURITY.md.

### Changed

- README badge that still said observe now names the live Hermes profile as enforce. The table already did.
- README dest-reads the live atoms profile as enforce. C1 strangler-observe is named. Badge matches.
- README leads with stakes, then the three-object invention at length, then maps. Runtime grade is stated as fact. Supervisory reader-orders and the short-sentence opening run are gone. BREAK is the J3 negative-control file. The apply-path fuzzer caller with `judge_apply_verdict=True` is named; `evaluate_tool_call` defaults that flag to True. PDP evaluate is labeled a pre-tool call. The grade table's Here column names the allowlist as the other roof. The live-mount flag is `judge_apply_verdict` everywhere. 

### Fixed
- `strip_check.sh` runs every recipe row, including a last row with no newline, and keeps strip stdin from eating later rows.

- `atom.condition.confidential_tag_in_clean_export` carried a bare `relaxations` mapping after the public extract removed its session pattern, and every firing raised `AttributeError`. With no pattern there is no relaxation, so it is now `relaxations: []`.
- The recursive-delete rule in `irreversible_operations.yaml` no longer cites AIID 1178. That incident was a failed mkdir followed by moves that overwrote files, which no match kind in the file can see, so the citation claimed coverage the rule never had.
- Judge price-table tests pin `when=` to the introductory expiry (`2026-08-31`) and the day after. After that date, `cost_usd(when=None)` uses post-intro rates. The $0.25 stage-one wall is unchanged.
- The published `SHA256SUMS` was generated from a Windows working tree, so 81 of its 110 rows did not match the repository that consumers clone. Regenerated from repository bytes.
- First push of a new branch resolves craft BASE to the origin default, so required craft jobs do not fail on an all-zero `github.event.before`. Pack SoT is the vault `repo-floor` copy. 
