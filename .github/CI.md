# Development CI

`RC CI` (`.github/workflows/rc.yml`) runs on every push to `rc` and every pull
request targeting `rc`, including workflow-only and documentation-only changes.
It has read-only repository permissions and does not publish downloads.
The existing upstream branch workflows are unchanged.

RC CI and manual CLI builds use `release/DEFAULT_BUILD_TAGS_RC`. This profile
excludes `with_naive_outbound`, `with_manager`, and `with_admin_panel`. Neither
workflow builds Cronet/NaiveProxy or admin panel assets, and neither installs
frontend dependencies. Publication regression tests use the runner's existing
Node.js and its built-in test runner. The general Makefile and other release
profiles retain their existing behavior.

## Checks

- **Tests and build**: Ubuntu and Go 1.26.7. Runs the main module's full test
  suite with the RC tags and repository linker flags, builds the CLI, and runs
  `version`. Tests execute through `sudo` on the disposable runner so root-only
  network tests are exercised.
- **Local routing integration**: Runs the nested test module's HTTP self-test,
  SOCKS/mixed UDP timeout tests, and all `TestRouteUseSniffedDestination*` cases.
  These use local listeners and controlled endpoints. A temporary modfile
  replaces developer-local sibling paths using the main module's replacement
  directives; neither checked-in module file is changed. Dependencies are
  resolved with `-mod=mod` only in this temporary file.
- **New-code lint**: Runs golangci-lint 2.13.2 using `.golangci.yml`. For PRs,
  the baseline is the merge-base with the PR's base commit; for pushes, it is
  the merge-base with the previous branch tip. Existing unrelated diagnostics
  are not made blockers for every new change. The analyzer still loads the
  main module; type/loading failures remain failures.

Go uses `GOTOOLCHAIN=local` after setup, so version incompatibilities fail
explicitly instead of silently downloading a different compiler.

## Manual self-test downloads

Run **Actions → RC self-test build → Run workflow**, selecting branch **rc**.
`.github/workflows/rc-build.yml` only accepts manual runs on this branch; pushes
and pull requests never publish downloads. Android is not built.

The four native build jobs use Go 1.26.7 and each run `sing-box version` before
uploading an archive:

| Platform | Architecture | Runner | CGO |
| --- | --- | --- | --- |
| Linux | amd64 | ubuntu-24.04 | disabled |
| Linux | arm64 (aarch64) | ubuntu-24.04-arm | disabled |
| macOS | amd64 (Intel) | macos-15-intel | enabled |
| macOS | arm64 (Apple Silicon/aarch64) | macos-15 | enabled |

Only after all four jobs succeed does the publish job update the moving
`rc-test` tag and its non-draft pre-release. It is not marked as the latest
release. Runs are serialized to prevent overlapping replacements. Each archive
contains the executable, LICENSE, and BUILD_INFO.txt with its version, source
commit, target, and tags. The self-test version is
`0.0.0-rc-test.<run-number>.<attempt>.g<short-sha>` and does not require any Git
tags in the fork. General version discovery ignores `rc-test` and other
non-version tags, matching only `v[0-9]*`.

The following fixed URLs allow downloads without login while the repository
remains public. They become available after the first successful manual run:

- https://github.com/lucifer9/sing-box-extended/releases/download/rc-test/sing-box-rc-test-linux-amd64.tar.gz
- https://github.com/lucifer9/sing-box-extended/releases/download/rc-test/sing-box-rc-test-linux-arm64.tar.gz
- https://github.com/lucifer9/sing-box-extended/releases/download/rc-test/sing-box-rc-test-macos-amd64.tar.gz
- https://github.com/lucifer9/sing-box-extended/releases/download/rc-test/sing-box-rc-test-macos-arm64.tar.gz
- https://github.com/lucifer9/sing-box-extended/releases/download/rc-test/SHA256SUMS

The workflow summary also lists these links. Replacement is not atomic: during
an update a download can briefly be missing or refer to a different build from
another file. Verify SHA256SUMS and retry after the run completes if necessary.
A failed publish job reports failure and can leave partially replaced assets;
it does not report the release as successfully updated. Per-run Actions
artifacts remain available for 14 days and require GitHub login.

No signing certificates, GPG keys, or custom secrets are needed. Only the
publish job receives `contents: write`, using the automatic `GITHUB_TOKEN`.
Its tag/release events do not trigger the existing Docker/Fury publication
workflows; do not replace it with a PAT. The builds are for developer self-tests,
with no distribution signing or macOS notarization.

For a local build with the same tags, use:

```sh
make build_rc
# Optional explicit version:
make build_rc VERSION=rc-test-local
```

`build_rc` reuses `build` with the RC tags and reads the version using the local
`cmd/internal/read_tag`. It writes `sing-box` in the repository root. Use this
entry point rather than `make release`: the latter intentionally builds the
admin panel and NaiveProxy for the existing general release pipeline.

## Coverage boundaries

The local integration job is intentionally a selected suite, not the entire
nested test module. Other tests require Docker images, external services, or
platform-specific features; full release-tag integration runs also currently
report KCP initialization goroutines through the leak checker, even when no
tests are selected. Add suitable self-contained integration tests to the
workflow's explicit selection as coverage grows. This does not suppress those
failures or claim that the full integration suite passed.

New-code lint covers the main module, not the nested integration module.
Whole-configuration schema regeneration is not a gate yet: the existing schema
generator rejects an unmapped `badoption.Regexp` type. Neither limitation is
hidden with an ignored failure step.

Branch protection and required-status policies are configured separately in
GitHub. Defining this workflow does not enable them automatically.
