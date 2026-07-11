# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately through GitHub's
[private vulnerability reporting][gh-pvr] for this repository. Do not
open a public issue or pull request for security problems.

A maintainer will acknowledge your report and coordinate a fix and
disclosure timeline with you.

[gh-pvr]: https://github.com/matthewjhunter/airlock/security/advisories/new

## Supported Versions

The latest tagged release receives security fixes. Older releases may
receive backports at the maintainer's discretion.

## Scope

In scope: the `wrap` and `unwrap` packages -- the fence primitive, the
delimiter neutralizer, and the JSON recovery scanner.

Out of scope: vulnerabilities in the Go standard library or toolchain
should be reported to the Go project. If one materially affects this
module, please still let us know so we can raise the floor or document it.

## Threat model and honest bounds

airlock provides mitigations, not guarantees. Read these before relying on
it, so you deploy it where it actually helps.

### `wrap` -- fencing untrusted text into a prompt

`wrap` implements prompt-injection **spotlighting**: it encloses untrusted
spans in a per-call, unguessable `crypto/rand` nonce delimiter
(`<untrusted-{nonce}> ... </untrusted-{nonce}>`) and neutralizes any
fence-shaped tag in the content first, so a stored value cannot predict or
forge the delimiter to break out.

What it does **not** do:

- **It is not a guarantee that the model obeys the fence.** Spotlighting
  raises the cost of a successful injection; it does not make the model
  provably ignore instructions inside the fence. A sufficiently capable or
  poorly-aligned model may still be steered. Treat `wrap` as defense in
  depth, not a control boundary you can lean your whole design on.
- **You must actually name the nonce in the trusted region of the prompt**
  and instruct the model to treat the fenced span as data. `wrap` builds the
  fence; it cannot write the surrounding instruction for you. A fence with no
  accompanying "this is data" clause is close to useless.
- **It assumes you own both ends of the prompt.** The technique works because
  the caller controls the trusted region *and* the model. It does not defend
  a boundary where some other party assembles the prompt (for example, the
  tool-result -> host-agent boundary of an MCP server -- there the server
  cannot forge a trusted delimiter into a prompt it does not own).
- **Neutralization deliberately preserves tags carrying attributes** (e.g.
  `<article id="1">`), so genuine markup in stored content survives for the
  model to read. Only bare or nonce-suffixed fence tags are stripped.

### `unwrap` -- recovering JSON from a model reply

`unwrap` extracts the first balanced JSON value from model output with a
string-aware scanner, tolerating markdown code fences and surrounding prose,
and validates the result with `encoding/json` before returning it.

What it does **not** do:

- **It does not validate meaning, only shape.** `unwrap` guarantees the bytes
  are well-formed JSON that fit your Go type; it does not judge whether the
  content is honest or safe. If the model was successfully injected, the JSON
  it returns is well-formed *and* attacker-influenced. Validate and bound the
  decoded values yourself.
- **"First balanced value" is a heuristic.** When a reply contains several
  JSON values, `unwrap` returns the first one. That matches the common
  "model emitted one object, maybe with prose around it" case; it is not a
  general multi-document parser.
- **It is lenient by design.** Tolerating fences and prose is a feature for
  real model output, but leniency is slack. Pair it with a strict schema /
  type on the Go side so the decoded value cannot carry more than you expect.
