# Edge core

This crate owns the mio data plane and bounded runtime command processing.

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `lib.rs` | HTTP proxy state machine, bounded command queue, and snapshot mio runtime. | Performs nonblocking socket work; publishes read-only runtime facts after listener registration. |
