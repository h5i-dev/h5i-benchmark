# h5i-benchmark

Worked solutions to public pentesting corpora. A general-purpose agent running
the standard Opus 5.0 model solved the benchmark instances using
[h5i](https://github.com/h5i-dev/h5i), specifically `h5i browser` and the
`h5i websec` plugin, and produced the solutions in this repository.

The repository currently covers two corpora:

| Corpus | Solved | Details |
| --- | ---: | --- |
| [XBOW Validation Benchmarks](https://github.com/xbow-engineering/validation-benchmarks) | 100/104 | [`examples/xben/README.md`](examples/xben/README.md) |
| [Argus Validation Benchmarks](https://github.com/pensarai/argus-validation-benchmarks) | 54/60 | [`examples/argus/README.md`](examples/argus/README.md) |

Each solution accepts a URL and prints a flag. The corpus-specific runner
checks that output against the exact flag for that benchmark; a test passes
only when the strings match.

## What this measures

The agent used h5i against running benchmark instances to inspect the applications, 
develop exploits, and retrieve flags. It used the general-purpose Opus 5.0 model, 
without benchmark-specific training or fine-tuning.

However, this was not a clean test of novel vulnerability discovery. The benchmarks 
and their writeups were already public and may have appeared in the model’s training data. 
We therefore make no claim that the vulnerabilities were new or that the results measure performance on unseen targets.

Instead, this repository evaluates whether h5i can support the requests and interactions needed
to exploit a broad range of applications, including multi-service scenarios.

## Common setup

Both corpora require Docker with the Compose plugin and h5i with the `websec`
plugin installed:

```bash
cargo build --release --workspace
./target/release/h5i plugin install websec --from target/release/h5i-websec
```

By default, solutions invoke `h5i` from `$PATH`. Set `H5I` to use a specific
build. See the corpus README for cloning, runner, fixup, and coverage details.

## The common pattern

Most solutions follow roughly the same sequence:

1. Run `h5i browser open --capture` against the target so every message is
   recorded.
2. Interact with the application until it produces the request to be tested.
3. Modify and resend that request using `h5i websec replay req_N --set …`.
4. Read the response and print the flag.

Some scenarios additionally require other protocols or services. Those
corpus-specific differences are described in the two linked READMEs.
