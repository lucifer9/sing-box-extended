# Development CI

`Dev CI` runs on every push to `dev` and every pull request targeting `dev`,
including workflow-only and documentation-only changes. It has read-only
repository permissions and does not publish releases, images, or packages.
The existing upstream branch workflows are unchanged.

## Checks

- **Tests and build**: Ubuntu, Go 1.26.7, and Node.js 22. Installs the admin
  panel's locked npm dependencies, builds and packs its embedded assets, runs
  the main module's full test suite with the repository release tags and linker
  flags, builds the CLI, and runs `version`. Tests execute through `sudo` on the
  disposable runner so root-only network tests are exercised.
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
