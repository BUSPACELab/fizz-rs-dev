# tls_bench

This crate ships a small binary that runs the same Tokio echo workload while changing only what sits above the TCP socket. That lets you compare plain TCP, TLS via tokio-rustls and rustls, and delegated TLS through the parent `fizz_rs` crate.

The `tcp` backend uses nothing but `tokio::net::TcpStream`. It is the cheapest case here: kernel and Tokio scheduling, no TLS. The `rustls` backend adds TLS 1.3 using tokio-rustls and rustls, with a short-lived self-signed certificate from rcgen. The `fizz` backend uses `ServerTlsContext` and `ClientTlsContext` from fizz-rs, including the FFI path and `spawn_blocking` work during accept and connect.

This setup does not isolate “async overhead” alone. Crypto, record handling, and the C++ stack all differ between backends. What you get is a practical question for one fixed pattern: on this machine, how does delegated fizz-rs line up against plain TCP and against rustls for the same echo shape?

## What it measures

Everything runs in a single Tokio multi-thread runtime. The server binds `127.0.0.1:0` and accepts as many connections as you configure. Each client connects once. After the path is ready (immediate for `tcp`, after the TLS handshake for `rustls` and `fizz`), each client repeats a fixed number of rounds. In each round it writes `batch_size` bytes, the server echoes them, and the client reads them back.

Timing covers the whole scenario from the moment the address is known until every client and server handler has finished. The tool runs that scenario several times (`--runs`), throws away optional warmup passes (`--warmup`), and reports the median wall time in milliseconds. Throughput in the CSV is derived from `total_bytes`, defined as twice the product of `connections`, `rounds`, and `batch_size` (counting payload bytes moving both directions), divided by that median time. For numbers you care about, build and run with `--release`.

## Prerequisites

Run Cargo from the fizz-rs-dev repository root. This crate depends on `fizz_rs` through a path of `../..`, so the layout matters. The `fizz` backend expects the same PEM fixtures as the library tests: `tests/fixtures/fizz.crt` and `tests/fixtures/fizz.key` under the repo root. If those files are missing, the tool still runs but skips `fizz` and records an error in the CSV. Compiling `tls_bench` compiles all of `fizz_rs`, including the native Fizz build from `build.rs`, so the first build can take a long time.

## Command-line options

You must pass either `--backend` with one of `tcp`, `rustls`, or `fizz`, or `--all-backends` to run all three in sequence with the same numeric settings.

`--worker-threads` sets the Tokio worker count (default 4). `--max-blocking-threads` sets the blocking thread pool size (default 512). For `fizz`, accept and connect use `spawn_blocking`; if you push many concurrent connections, raise this limit so the blocking pool is less likely to cap throughput.

`--connections` is how many clients run at once (default 8). `--batch-size` is the echo payload size in bytes (default 16384). `--rounds` is how many echo cycles each client performs (default 64). `--warmup` is how many full runs to execute before recording (default 0). `--runs` is how many timed runs feed the median (default 3). With `--csv-header`, the first line of output is a column header row.

`--preset small` replaces the six numeric defaults at once: 4 workers, 512 max blocking threads, 8 connections, 16384 byte batches, 64 rounds, 3 runs. `--preset large` uses 32 workers, 2048 max blocking threads, 128 connections, 262144 byte batches, 64 rounds, and 5 runs. Presets do not change `--warmup`; you can still set warmup separately.

## CSV output

Each result line contains, in order: `backend`, `worker_threads`, `max_blocking_threads`, `connections`, `batch_size`, `rounds`, `wall_ms`, `total_bytes`, `mb_per_s`, and `error`. The backend name is always lowercase (`tcp`, `rustls`, or `fizz`). The error field is empty when the run succeeded; otherwise it holds a short code or message, with commas stripped from messages so the line stays parseable as CSV.

## Examples

From the repo root, compare every backend once with a header row:

```bash
cargo run -p tls_bench --release -- --csv-header --all-backends
```

Use the large preset but only the fizz backend:

```bash
cargo run -p tls_bench --release -- --preset large --backend fizz
```

Sweep thread count and load manually:

```bash
cargo run -p tls_bench --release -- --csv-header --all-backends \
  --worker-threads 16 --connections 64 --batch-size 65536 --rounds 32 --runs 5
```

## CI and local tips

Continuous integration only builds this package (`cargo build -p tls_bench`) so it keeps compiling. No job asserts on benchmark timings.

If another process is already using the default target directory, Cargo may print “Blocking waiting for file lock on build directory.” Rust-analyzer often runs `cargo check` in the background; wait for it or stop it, or point Cargo at a fresh target directory, for example `CARGO_TARGET_DIR=target/tls_bench cargo run -p tls_bench --release --` followed by your flags.

For TLS-to-TLS comparisons, read `rustls` and `fizz` side by side. The `tcp` row is still useful as a floor so you can see how much of the end-to-end time is tied to TLS and your stack versus the bare echo pattern on the loopback interface.
