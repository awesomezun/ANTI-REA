# Scope-comparison fixture

This synthetic C++ score transformation accepts unsigned 32-bit input pairs and
prints one unsigned 64-bit decimal result per pair. It is not cryptography or an
authentication/licensing system.

The semantic chain is `antirea_score` -> `antirea_prepare` -> `antirea_mix` ->
`antirea_adjust`; `antirea_score` calls the three stages and passes their results
along. Per-build constants occur in preparation, mixing and adjustment.

`core` mode requests VM protection only for `antirea_mix`. `expanded` mode uses
the scope analyzer to discover its callers and their helpers from the call graph.
The policy deliberately leaves `sensitive_functions` empty so this discovery is
not replaced by a hand-written list. Both use the same Kagura VM pass, so the comparison changes protection
scope, not protection strength. The transparent `antirea_present_score` wrapper
is an explicitly reviewed public boundary and must remain native.

`core.cpp` is the complete analyzed module. `main.cpp` is a separately compiled,
reviewed public stdin/stdout adapter; neither it nor the standard library is
claimed to have been analyzed or protected. Constants are immediate operands,
not secret data globals. No global/string encryption claim is made.

The checked-in header contains public smoke defaults. Real runs supply a fresh
private `generated_config.h` through `-ConfigInclude`. The build fails if a
selected function lacks a VM wrapper/nonempty bytecode blob or if the public
boundary is accidentally virtualized.
