# Core contracts

The adaptive subsystem exchanges typed, immutable records rather than loose
dictionaries.  The registry broker resolves `ResolvedNpmRelease`, verifies its
tarball integrity, and produces the Phase 1 records: `NpmArtifact`,
`PackageEntrypoint`, `PackageExport`, and `PackageMap`.

`DependencyClosure` contains only verified runtime tarballs plus their exact
read-only `node_modules` installation paths. Unsupported dependency sources
and limits are records in `unresolved`, not implicit omissions.

Later phases add `EnvironmentProfile`, `HarnessPlan`, `HarnessRun`,
`CoverageReport`, and `AdaptiveResult`.  Import probes additionally emit a
bounded list of observed `import`/`require` outcomes. Every record must carry
the root artifact SHA-256 or reference a record that does.
