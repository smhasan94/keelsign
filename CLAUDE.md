# keelsign

Post-quantum firmware signing kit. Sign firmware on the host with ML-DSA or LMS/HSS
(optionally hybrid with Ed25519) and verify it on the device, keeping MCUboot's image
format so MCUboot and embassy-boot users keep their existing update pipeline.

Plan: Linear, team Shakooky, project "keelsign" — epics SHA-8 … SHA-15, each with
sub-issue tickets carrying Scope, Acceptance criteria and Test plan as checkboxes.

## Crate layout

| Crate | Kind | Purpose |
|---|---|---|
| `keelsign` | host CLI | `keygen` / `sign` / `verify` / `inspect` MCUboot-format images |
| `keelsign-verify` | `no_std`, no heap | Parses header + TLV area, hashes image in chunks, verifies ML-DSA-44/65 and LMS/HSS, hybrid with Ed25519; typed errors |
| `keelsign-embassy` | `no_std` | Adapter for embassy-boot |
| `keelsign-ffi` | staticlib | C ABI + cbindgen header for MCUboot's `MCUBOOT_USE_CUSTOM_CRYPTO` hook (`libkeelsign`) |

Licence: MIT OR Apache-2.0.

Boards: nRF52840-DK (Cortex-M4F, `thumbv7em-none-eabihf`), Raspberry Pi Pico 2 W
(RP2350, Cortex-M33, `thumbv8m.main-none-eabihf`), NUCLEO-U575ZI-Q (Cortex-M33),
Raspberry Pi Debug Probe.

## Conventions

- No `unsafe` outside `keelsign-ffi`. Every other crate has `#![forbid(unsafe_code)]`.
- No panic paths in `no_std` code. `no_std` crates deny `clippy::panic`,
  `clippy::unwrap_used`, `clippy::expect_used`, `clippy::indexing_slicing`.
- `cargo clippy --all-targets -- -D warnings` is clean; `cargo fmt --check` is clean.
- Every acceptance criterion and test-plan case has a **named test** (or, if it needs
  physical hardware, a named manual procedure in `docs/` that the verifier marks
  NEEDS-HARDWARE).
- Test fixtures are regenerated only by script (`scripts/`), never edited by hand.
- One ticket per branch and PR. Use the Linear branch name
  (`hasansharukh/sha-NN-...`). PR title starts with the ticket ID.
- `ml-dsa` must be pinned to a version including the fixes for CVE-2026-24850 and
  GHSA-h37v-hp6w-2pp8.
- Never widen scope beyond the ticket. Follow-ups become new Linear issues.

## Per-ticket loop

Model split: **planning and code review on Claude Fable 5.1; implementation and
testing/verification on Claude Opus 5.5.**

1. **Plan** — `planner` agent (Fable 5.1) reads the Linear ticket and the repo and
   writes an implementation plan mapping every acceptance criterion and test-plan
   checkbox to a named test or documented manual procedure. The plan is shown to the
   user and approved before implementation.
2. **Branch** — create the ticket's branch from `main`.
3. **Implement** — `implementer` agent (Opus 5.5) implements exactly the approved plan,
   writes the tests, runs the suite, reports passed / failed / needs-hardware.
4. **Verify** — `verifier` agent (Opus 5.5) runs a real command for every checkbox and
   records PASS / FAIL / NEEDS-HARDWARE with evidence. Any FAIL goes back to step 3.
5. **Review** — `reviewer` agent (Fable 5.1) reviews the branch diff; blocking findings
   go back to step 3.
6. **PR** — open the PR with the verification table and review summary; post the same
   to the Linear ticket as a comment. Tick only the checkboxes with PASS evidence.
7. A ticket is Done only when all boxes are ticked (NEEDS-HARDWARE items verified on the
   board by a human) and the review has no blocking findings.

Actions that only the human can do (ordering hardware, publishing to crates.io,
pushing to GitHub, flashing boards) are listed in the PR as manual steps, not faked.
