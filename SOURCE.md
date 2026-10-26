# Source of truth

This repo's source of truth is **amber-git** (`https://amber-git.stackwell.tech/attestation-envelope.git`), not
GitHub. `origin` points there; GitHub (`stackwell-labs/attestation-envelope`) is a read-only mirror
that amber-git updates on every accepted push, so GitHub Actions keep running.

- Push branches to `origin` only. The mirror creates the GitHub branch within
  seconds; open the PR on GitHub after it appears.
- Land with `ops/scripts/land_amber.py stackwell-labs/attestation-envelope <sha>`, never the GitHub
  merge button: the next mirror push of `main` overwrites a GitHub-side merge.
- Never push to `github`. A branch pushed there exists only on GitHub.
