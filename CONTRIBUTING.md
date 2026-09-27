# Contributing

## Branches

Create branches from an updated `dev` branch using the following naming convention:

- `feature/<name>`
- `fix/<name>`
- `refactor/<name>`
- `test/<name>`
- `docs/<name>`
- `chore/<name>`

Do not commit or push directly to `main` or `dev`.

## Commits

Use Conventional Commits:

- `feat:`
- `fix:`
- `test:`
- `refactor:`
- `docs:`
- `chore:`
- `ci:`

Keep commits focused on a single purpose.

## Pull Requests

Each change should:

- Have a related issue.
- Be submitted through a Pull Request.
- Be tested locally.
- Pass the configured CI checks.
- Be reviewed before merging.
- Use `Closes #<issue-number>` in the PR description.

## Branch workflow

- Create working branches from `dev`.
- Open Pull Requests from working branches into `dev`.
- Do not open working-branch Pull Requests directly into `main`.
- Only `dev` may be merged into `main`.
- Delete working branches after they are merged.

Expected workflow:

```text
feature/*  ─┐
fix/*      ─┤
refactor/* ─┤
test/*     ─┼──> dev ──> main
docs/*     ─┤
chore/*    ─┘
```
