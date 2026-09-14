# Decisions

## 2026-07-22: Start with artifact identity

Static and runtime evidence cannot be correlated when analysis operates on a
mutable package specifier alone.  The adaptive engine therefore stores and
hashes a tarball before it maps or executes anything.

## 2026-07-22: Native V8 coverage is the initial collector

Node V8 coverage avoids target-source rewriting and works across CommonJS and
ESM.  Istanbul-style reports can be added as an offline conversion step later.
