# Source of truth

This repo's source of truth is **amber-git** (`https://amber-git.stackwell.tech/attestation-envelope.git`), not
GitHub. `origin` points there; GitHub (`stackwell-labs/attestation-envelope`) is a read-only mirror
that amber-git updates on every accepted push.

- Push branches to `origin` only.
- Land by pushing the green commit to `main` on `origin` once amber-ci has
  passed it, with no PR (`~/devbox/docs/session-rules.md`, Landing). Never
  use the GitHub merge button: the next mirror push of `main` overwrites a
  GitHub-side merge.
- Never push to `github`. A branch pushed there exists only on GitHub.
