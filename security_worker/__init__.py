"""Kali security worker: an optional, independently deployable scanner.

The main Vibe Coding QA API never runs a security tool itself. When an operator
registers a worker, the API sends a *job* (a fixed tool list plus a validated
target) over authenticated HTTP and the worker runs it inside an unprivileged
container. This package holds the code that both sides reason about:

* :mod:`security_worker.registry` - the allow-listed tool registry and the fixed
  command templates. No caller ever supplies a command line.
* :mod:`security_worker.normalize` - the shared finding schema and dedupe keys.
* :mod:`security_worker.adapters` - per-tool output parsers.
* :mod:`security_worker.runner` - bounded, cancellable process execution.
* :mod:`security_worker.server` - the worker's authenticated HTTP API.

Importing this package must stay dependency-free (standard library only) so the
worker image needs nothing beyond the Kali tools themselves.
"""

__version__ = "0.1.0"
