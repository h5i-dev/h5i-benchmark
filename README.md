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

The agent worked against running benchmark instances and used h5i to inspect
the applications, develop the exploits, and retrieve the flags. It was not
given the published writeups and did not directly consult them during the
experiment. It used the ordinary, general-purpose Opus 5.0 model, not a model
specially trained or fine-tuned for this benchmark.

This is not, however, a clean test of previously unseen vulnerability
discovery. The benchmarks and their writeups had already been public from
multiple sources before the experiment. They may therefore have appeared in
the model's training data, and this experiment cannot establish whether or how
much that prior exposure affected the results. The repository makes no claim
that these are new vulnerabilities or that the scores measure performance on
truly novel targets.

What this repository tests is the tool itself. Can h5i express the requests
and interactions required by an exploit, send them accurately, record them,
and expose the responses? Does it continue to do so across many applications
and multi-service scenarios?

A corpus with known answers is useful for evaluating those questions because
failures are unambiguous. The exploit is already known to work; if a solution
does not retrieve the expected flag, either the environment or h5i is missing
something the scenario requires.

The agent supplied the reasoning and payloads; h5i sent the requested traffic,
recorded it, and exposed the responses. h5i itself does not generate payloads
or scan for vulnerabilities. The reasoning behind this separation is
described in W1 of `docs/design/design-websec.md` in the h5i repository.

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
