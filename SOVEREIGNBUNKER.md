# SovereignBunker

SovereignBunker is Sovereign Technology's maintained fork of
[Bunker46](https://github.com/dsbaars/bunker46), the NIP-46 remote signer by Djuri Baars (MIT). We run it
as our production signer. It stays mergeable with upstream: we merge upstream releases in, offer our fixes
back as pull requests, and keep the diff small.

## Where it lives

| What                                                    | Where                                                  |
| ------------------------------------------------------- | ------------------------------------------------------ |
| Origin: code, pull requests, CI, release tags           | https://github.com/SovereignTechnology/sovereignbunker |
| Private mirror we also deploy through                   | GitLab `sovtech/sovereignbunker`                       |
| Upstream                                                | https://github.com/dsbaars/bunker46                    |

GitHub is always pushed first and must never lag: GitLab only ever receives commits GitHub already has. Merges
into `main` are done locally, never with GitHub's or GitLab's merge button.

## What differs from upstream

- **Carried fixes** that we also offered upstream, listed newest first:
  - `connect` replies `ack` unless the request presents the connection's own secret. This is upstream
    PR #26; rust-nostr clients such as ngit 3.x need it to sign at all.
  - A relay connect timeout ("WebSocket was closed before the connection was established") is treated as
    transient, not fatal. This is upstream PR #25, which fixes #24.
- **Branding:** the web UI title, header, login and register screens and the API docs title say
  SovereignBunker.
- **Builds:** the Dockerfile base images are pinned by digest.

### What deliberately still says `bunker46`

These are identifiers, not branding. Renaming them would break running installs or make every upstream
merge conflict:

- the `@bunker46/*` package names;
- the database and role names;
- environment variable keys;
- browser storage keys (`bunker46-settings`, `bunker46-ui`);
- the event channel prefix;
- the TOTP issuer and WebAuthn RP name (changing them would split existing authenticator entries);
- the key-derivation salt `bunker46:encryption-key:v2`. Changing it makes every stored key
  undecryptable, so never touch it.

## Merging

- Our own changes go through merge requests and are squashed into one commit authored
  `sovtech <git@sovtech.pro>`.
- Upstream releases come in as a real two-parent merge of `upstream/main`, never a squash, so later merges
  stay clean.
- A change we want upstream is also opened as a pull request against `dsbaars/bunker46` from a branch based
  on upstream `main`.

## CI and releases

- CI is GitHub Actions, for build and test only (`.github/workflows/ci.yml`: lint, format, build, unit, migrations
  and database integration, Playwright e2e). It runs on pushes to `main` and on every pull request, with a
  read-only token and no secrets.
- Every action is pinned to a commit SHA, and the repository setting that requires SHA pinning is on, so an
  unpinned action (for example one that arrives with an upstream merge) fails loudly: re-pin it. Only
  GitHub-owned actions plus the few named in the allow-list may run.
- Release tags are `sovtech-vMAJOR.MINOR.PATCH` and must point at a commit already in `main`. The tag runs
  `.github/workflows/sovtech-release.yml`: CI first (through `workflow_call`), then the server and web OCI images
  are built from source and uploaded as an artifact with `SHA256SUMS`. Nothing is pushed to a registry.
- Our deploy imports the images by digest, and only after checking each tar against the sums printed in that run's
  log (not the artifact's own file).
- Never a network service, a tunnel or an idle job on GitHub's runners.

## License

MIT, as upstream. See [LICENSE](LICENSE); Djuri Baars' copyright notice is kept, and ours covers the
SovereignBunker changes.
