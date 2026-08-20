# Comments

A comment earns its place or it goes. The bar is that a competent reader of the code would not reach the same conclusion without it.

## Write one for

- A citation: the spec section and the sentence a rule comes from, so the next reader can check the ground rather than trust the code.
- A constraint the code cannot show: an ordering another party imposes, a value that has to outlast a round trip, a limit measured rather than assumed.
- A decision with a cost: why the obvious approach does not work here.

## Do not write one for

- What the code already says. `// reads the cookie` above a function that reads the cookie is noise.
- What was removed, rejected or used to happen. State the design that is there. History belongs in the changelog and in `docs/adr/`.
- A restatement of the identifier. If a one-line constant needs nine lines of prose, the prose is doing the naming's job badly.
- Reassurance. "This is safe because" without a mechanism is a comment that ages into a lie.

## Length

Match the code. One line of prose for one line of code is usually one line too many, and a paragraph over a three-line function is a paragraph looking for a better home: the package doc, an ADR, or `docs/`.

When a comment grows past a few lines, ask whether it is documentation that escaped. Deployment reasoning belongs in `docs/`, an architectural decision in `docs/adr/`, a user-facing rule in the guide for that command.

## Tests

A test comment says the requirement the test encodes, positively, so a rule that later changes is found by reading it. It never asserts that an old behavior is absent.
