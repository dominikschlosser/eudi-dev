# Domain Docs

How agents use this repo's domain documentation when exploring the codebase.

This repo is **single-context**: one `CONTEXT.md` and one `docs/adr/` at the root.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root, or
- **`CONTEXT-MAP.md`** at the repo root if it exists. It points at one `CONTEXT.md` per context. Read each one relevant to the topic.
- **`docs/adr/`**: read the ADRs that touch the area you are about to work in. In multi-context repos, also check `src/<context>/docs/adr/` for context-scoped decisions.

If any of these files are missing, proceed without comment. The `/domain-modeling` skill creates them when terms or decisions get resolved.

## File structure

Single-context repo (most repos):

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-event-sourced-orders.md
│   └── 0002-postgres-for-write-model.md
└── src/
```

Multi-context repo (presence of `CONTEXT-MAP.md` at the root):

```
/
├── CONTEXT-MAP.md
├── docs/adr/                          ← system-wide decisions
└── src/
    ├── ordering/
    │   ├── CONTEXT.md
    │   └── docs/adr/                  ← context-specific decisions
    └── billing/
        ├── CONTEXT.md
        └── docs/adr/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Avoid synonyms the glossary explicitly avoids.

A concept missing from the glossary means one of two things. Either you are inventing language the project does not use (reconsider), or the glossary has a gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, say so explicitly:

> _Contradicts ADR-0007 (event-sourced orders), but worth reopening because…_
