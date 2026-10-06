# CLI output can be automated

eudi-dev runs in CI pipelines and test harnesses as much as in a terminal. Scripts read its output with `jq` or a JSON parser, so `--json` output is an interface. Text output is for people.

## One document on stdout

With `--json`, a command writes exactly one JSON document to stdout and nothing else. Progress, banners, hints and warnings go to stderr. A parser reads all of stdout. A second document or a stray line breaks it just like a wrong field does.

- A command that returns data prints it as an object or an array. An empty result is an empty array (or an object holding one), never a sentence.
- A command that changes something prints an object that says what changed, such as `{"removed": 1, "id": "a1b2"}`.
- A command whose result is an artifact (a credential, a PEM certificate, a trust list JWT) prints the bare artifact without `--json`, so a script can use it as is. With `--json` it wraps the artifact in an object, such as `{"credential": "..."}`.
- A command that checks several things (`validate`) collects them in one document.

## Failures

A failing command exits non-zero and writes the error to stderr. A command that has a result and still fails, such as `validate` on an invalid signature, prints its document first, so a script sees what failed. Declining a consent request or letting it time out is a failure.

## Long-running commands

`wallet serve` and `serve` do not take `--json`. They run until stopped, so there is no single result. `wallet serve --log-format json` writes its log as one JSON record per line. `proxy --json` writes one JSON object per line for each OID4VP or OID4VCI exchange it captures (every exchange with `--all-traffic`) and nothing else on stdout. `wallet logs` and `proxy logs` refuse `--json` together with `--follow`. The shell completion commands print a script and do not take `--json`.

## Consequences

Text output may change between releases. The JSON documents only gain fields within a major version.

Each new command defines its `--json` document when it is added. Tests parse the whole of stdout as one JSON document, so a stray line fails them.
