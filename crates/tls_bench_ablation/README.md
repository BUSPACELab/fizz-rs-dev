# tls_bench_ablation

This crate is a contention-free variant of `tls_bench`. It runs the same echo workload across the same three backends (`tcp`, `rustls`, `fizz`), but arranges the Tokio runtime so that no worker thread ever has to multiplex more than one task. The goal is to strip scheduling and blocking-pool contention out of the picture so that whatever overhead remains — particularly in the `fizz` backend — is attributable to the work itself: the CXX FFI bridge, copies across the Rust/C++ boundary, crypto, record handling, and any synchronous waiting inside the delegated path.

Put differently: if `tls_bench` asks "how does each backend behave under a realistic concurrent load," this crate asks "what is the floor? What is the cost of a single TLS conversation when nothing is fighting over a worker or a blocking slot?"

## Design: one knob, two runtimes

There is one parameter that controls concurrency: `--pairs N`. It sets

```
clients = servers = connections = N
```

by construction. The benchmark then builds two Tokio multi-thread runtimes that share no threads:

- **client runtime**: `N` worker threads, `N` blocking threads, threads named `ablation-client`
- **server runtime**: `N` worker threads, `N` blocking threads, threads named `ablation-server`

Total blocking threads across both runtimes is `2N`, which matches the `max_blocking_threads = clients + servers` rule from the ablation spec. Server handlers never run on the same worker as clients, and the blocking pool each side uses for `spawn_blocking` (which the `fizz` backend needs for accept and connect) is sized exactly to its own demand.

The default is `--pairs 1`. At that setting you have one client talking to one server over one connection, with one worker on each side and one blocking thread available to each side. Every thread in the process has a dedicated, unambiguous job. That is the smallest configuration and the most flame-graph-friendly one: it produces a narrow profile where each frame corresponds to a specific responsibility.

## What it measures

The server listener is bound synchronously so the address is known before the client runtime starts dialing. The `std::net::TcpListener` is handed to the server runtime and converted to a `tokio::net::TcpListener` there — that single file descriptor is the only thing the two runtimes share. Each side then runs its half of the workload on its own runtime.

Timing covers the whole scenario. Wall clock starts just before the first client task is spawned and stops once every client and every server handler has finished (including the TLS handshake on each side for `rustls` and `fizz`). Each client performs `rounds` echo cycles of `batch_size` bytes in each direction. The tool runs the scenario `--runs` times after `--warmup` passes and reports the median wall time. Throughput is derived from `total_bytes = 2 * pairs * rounds * batch_size` divided by that median. For numbers you care about, build with `--release`.

Because this crate shares the exact `echo_serve` and `echo_client` implementations with `tls_bench`, you can cross-compare: the same workload in one shared runtime vs. the same workload split across two sized runtimes. A gap that stays large on the `fizz` backend in both setups is a gap you cannot explain away with scheduling pressure.

## Prerequisites

Run Cargo from the fizz-rs-dev repository root. This crate depends on `fizz_rs` via `../..`, so the workspace layout matters. The `fizz` backend expects the same PEM fixtures as the library tests: `tests/fixtures/fizz.crt` and `tests/fixtures/fizz.key` under the repo root. If those files are missing, the tool still runs but skips `fizz` and records an error in the CSV. Compiling `tls_bench_ablation` compiles all of `fizz_rs`, including the native Fizz build from `build.rs`, so the first build can take a long time.

## Command-line options

You must pass either `--backend` with one of `tcp`, `rustls`, or `fizz`, or `--all-backends` to run all three in sequence with the same numeric settings.

`--pairs N` is the concurrency knob (default 1). It simultaneously sets the number of clients, the number of server handlers, the number of connections, both per-runtime worker counts, and both per-runtime blocking-thread pools. Increase it only if you want to see how the ablated arrangement scales; for profiling, leave it at 1.

`--batch-size` is the echo payload size in bytes (default 16384). `--rounds` is how many echo cycles each client performs (default 64). `--warmup` is how many full runs to execute before recording (default 0). `--runs` is how many timed runs feed the median (default 3). With `--csv-header`, the first line of output is a column header row.

There are no presets here. The ablation is deliberately a single axis.

## CSV output

Each result line contains, in order: `backend`, `pairs`, `client_workers`, `server_workers`, `max_blocking_threads`, `batch_size`, `rounds`, `wall_ms`, `total_bytes`, `mb_per_s`, and `error`. The three worker-related columns are redundant with `pairs` by construction (they hold `pairs`, `pairs`, and `2 * pairs` respectively), but they are kept explicit so the CSV is self-describing and can be joined against `tls_bench` output without recomputation. The backend name is always lowercase. The error field is empty on success; otherwise it holds a short code or message with commas stripped so the line stays parseable as CSV.

## Examples

From the repo root, the smallest case with a header row — one client, one server, one connection, all three backends:

```bash
cargo run -p tls_bench_ablation --release -- --csv-header --all-backends
```

Flame-graph-friendly profiling of the `fizz` backend at 1-1-1. With named runtime threads, client-side and server-side frames are trivially distinguishable in the resulting graph:

```bash
cargo build -p tls_bench_ablation --release
samply record ./target/release/tls_bench_ablation \
  --backend fizz --pairs 1 --runs 1 --warmup 0 \
  --batch-size 65536 --rounds 256
```

Substitute `cargo flamegraph -p tls_bench_ablation --release -- ...` if you prefer that tool. Longer `--rounds` gives the profiler more signal once the handshake is past.

See how the ablated arrangement scales sideways — still no per-worker contention, but more concurrent conversations:

```bash
cargo run -p tls_bench_ablation --release -- --csv-header --all-backends \
  --pairs 8 --batch-size 65536 --rounds 32 --runs 5
```

## How this differs from `tls_bench`, and when to use which

Use `tls_bench` when you want a realistic picture: shared runtime, a bounded worker pool, many clients packed onto few workers, a large shared blocking pool. That is the shape production code actually has, and the numbers from it are the ones that matter for real deployment decisions.

Use `tls_bench_ablation` when a `tls_bench` result looks worse than you expected for the `fizz` backend and you want to check whether the gap is scheduling pressure (workers being stolen between clients and servers, blocking-pool saturation during handshakes) or something structural in the delegated TLS path. If the `fizz` gap relative to `rustls` narrows sharply when you switch from `tls_bench --preset small` to `tls_bench_ablation --pairs 1`, the answer is probably "contention." If the gap stays roughly the same, the answer is probably further up the stack — the CXX bridge, extra buffer copies, or blocking work that cannot overlap regardless of how many workers you give it. That second outcome is the one worth profiling.
