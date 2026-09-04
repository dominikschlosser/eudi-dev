# Comments

A comment stays only if a competent reader of the code would not reach the same conclusion without it.

## Write one for

- A citation: the spec section and the sentence a rule comes from, so the next reader can check it.
- A constraint the code cannot show: an ordering another party imposes, a value that has to outlast a round trip, a limit measured rather than assumed.
- A non-obvious decision: why the obvious approach does not work here.

## Do not write one for

- What the code already says. `// reads the cookie` above a function that reads the cookie adds nothing.
- What was removed, rejected or used to happen. State the design that is there. History belongs in the changelog and in `docs/adr/`.
- A restatement of the identifier. A one-line constant does not need nine lines of prose.
- Reassurance. "This is safe because" without naming the mechanism.

## Length

Match the code. One line of prose per line of code is usually one too many. A paragraph over a three-line function belongs in the package doc, an ADR, or `docs/`.

When a comment grows past a few lines, it is probably documentation. Deployment reasoning belongs in `docs/`, an architectural decision in `docs/adr/`, a user-facing rule in the guide for that command.

## Tests

A test comment states the requirement the test encodes, positively, so a rule that later changes is found by reading it.
