# Public interface: synthetic score CLI

This is a small local command-line demonstration, not a GUI application.
It reads pairs of unsigned 32-bit decimal integers (`0` through `4294967295`)
from standard input. For each pair it prints one unsigned 64-bit decimal score
on a separate line. Multiple pairs can be provided in one process.

The result is deterministic for a particular build. Different builds may use
different internal scoring constants. Input parsing, decimal formatting, and
the forwarding presentation adapter are public interface behavior; the internal
score calculation is the protection target. The score is synthetic and is not
used for cryptography, authentication, licensing, or access control.

The reconstruction task is to implement `solve(x, y)` with the same numeric
output as the provided executable for valid input pairs. No exact source-code
reconstruction is required. Standard-library I/O does not need to be cloned.
