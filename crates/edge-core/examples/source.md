# Edge core examples

These entrypoints are manual test tools. They are not packaged product binaries,
runtime dependencies, or release evidence collectors.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `http_framing_mutation_fuzz.rs` | Runs fixed-seed bounded request-parser, fragmented upstream-response-framer, and connection-event state-machine mutations on the stable Rust toolchain. | Pure in-process Core calls only; accepts 1..=1,000,000 cases, persists no corpus, prints only a case-count summary, and does not create release evidence. |
