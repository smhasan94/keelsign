# Release procedures

Human-only steps for ticket SHA-31: creating the GitHub repository and reserving the
crate names on crates.io. Agents never run these.

## GitHub repository

The empty repository `smhasan94/keelsign` already exists and is the `origin` remote.
Push, open the PR and watch CI:

```sh
gh auth switch -u smhasan94            # or: gh auth login
git push -u origin main
git push -u origin hasansharukh/sha-31-e11-order-hardware-reserve-crate-names-create-repo-ci
gh pr create --title "SHA-31: E1.1 — Order hardware, reserve crate names, create repo + CI"
gh run watch
```

If the repository is ever recreated from scratch:
`gh repo create smhasan94/keelsign --public --description "Post-quantum firmware signing kit (ML-DSA / LMS-HSS, MCUboot-compatible)"`.

CI (`.github/workflows/ci.yml`) must be green on the PR: fmt, clippy, tests, the
network repo checks (`cargo test -p repo-checks -- --ignored`) and
`cargo publish --dry-run` for both crates.

## crates.io placeholders

Publish the `0.0.1` name-reservation placeholders of `keelsign-verify` and `keelsign`.
Do this after the PR is merged, from a clean `main`.

Prerequisites:

- The crates.io account has a **verified email** address.
- The API token has the scopes **publish-new** and **publish-update**.
- The account that publishes is the one that will publish `0.1.0` (it becomes the
  owner).

Publish:

```sh
cargo login
cargo publish --dry-run -p keelsign-verify -p keelsign
cargo publish -p keelsign-verify -p keelsign
```

keelsign depends on keelsign-verify; publish keelsign-verify first (`cargo publish -p
keelsign-verify -p keelsign` publishes both in order).

Verify (test-plan case "`cargo search keelsign` lists both"):

```sh
cargo search keelsign --limit 10
```

Both `keelsign = "0.0.1"` and `keelsign-verify = "0.0.1"` must be listed.

Owner check (test-plan case "0.1.0 publish later not blocked"):

```sh
cargo owner --list keelsign && cargo owner --list keelsign-verify
```

The account that will publish `0.1.0` must be listed as owner of both crates. The
placeholders are `0.0.1`, so `0.1.0` is a strictly greater version and publishing it
later is not blocked (enforced locally by `packaging::publishable_versions_are_0_0_1`).
