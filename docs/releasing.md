# Releasing watermelon-pgp

The version lives in more places than `Cargo.toml`, and some steps happen only after the release
exists. Copy this list into the release PR (or an issue) and tick it off. `X.Y.Z` is the new
version; `A.B.C` the previous one.

A release takes two PRs (three if the UI changed) and one tag:

```
release-X.Y.Z    "Release X.Y.Z"          version, CHANGELOG, README
tag vX.Y.Z       on the merge commit      release.yml builds and publishes
website-X.Y.Z    "Website: version X.Y.Z" badge, tarball commands (after the release exists)
                 + screenshots PR if the UI changed
```

## 1. The release PR

- [ ] CI is green on `main`.
- [ ] `Cargo.toml`: `version` under `[workspace.package]` → `X.Y.Z` (every crate inherits it).
- [ ] `Cargo.lock`: `cargo update --workspace`, then check that only the workspace crates
      changed (`git diff Cargo.lock`). The release builds with `--locked`, so a stale lock
      file fails it.
- [ ] `CHANGELOG.md`: a `## [X.Y.Z] - YYYY-MM-DD` section above the previous release (rename
      `## [Unreleased]` if there is one). `release.yml` uses this section as the release notes
      and fails if it can't find `## [X.Y.Z]`.
- [ ] Until Windows support is done (issue #1), the notes call the Windows zip a preview for
      testing, and README's Install doesn't list it.
- [ ] A database schema change is called out in the CHANGELOG (what happens on upgrade, how to
      go back) and in the PR's **Merge Danger** as a one-way door.
- [ ] `README.md`: the status line (`> **Status: X.Y.Z.** …`), and Features, Install and Known
      issues for anything this release adds, changes or fixes.
- [ ] `docs/cli.md` and `docs/deployment.md` (Upgrading) match new commands, options and
      upgrade steps.
- [ ] Nothing else still names the old version:
      `git grep -nF A.B.C -- ':!CHANGELOG.md' ':!Cargo.lock'` (the website is updated later).
- [ ] The release dry run passes on the release branch. It builds and packages every target,
      writes the release notes and the Homebrew formula, and builds the image, but publishes
      nothing. The Windows build (`build (x86_64-pc-windows-msvc, windows-latest)`) also
      smoke-tests the unpacked zip: `--version`, `init` and `/healthz`, and that `watermelon.exe`
      needs no C runtime DLL (`dumpbin /dependents`):

  ```sh
  gh workflow run release.yml --ref release-X.Y.Z
  gh run watch "$(gh run list --workflow release.yml --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId')"
  ```

## 2. Tag

- [ ] The merge commit's CI run is green (its `ci-ok` job passed):

  ```sh
  git switch main && git pull --ff-only
  gh run list --workflow ci.yml --commit "$(git rev-parse HEAD)"
  ```

- [ ] Tag it (annotated, like the earlier tags) and push the tag:

  ```sh
  git tag -a vX.Y.Z -m "WatermelonPGP X.Y.Z"
  git push origin vX.Y.Z
  ```

  `release.yml` refuses a tag that doesn't match the version in `Cargo.toml`.

## 3. Check what `release.yml` published

- [ ] The run succeeded: `gh run list --workflow release.yml --event push --limit 1`,
      `gh run watch <id>`. (CI also runs on the tag.)
- [ ] `gh release view vX.Y.Z`: four tarballs, `watermelon-pgp-vX.Y.Z-<target>.tar.gz` for
      `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin` and
      `x86_64-apple-darwin`, the Windows preview `watermelon-pgp-vX.Y.Z-x86_64-pc-windows-msvc.zip`,
      and `SHA256SUMS` listing all five; the notes are the CHANGELOG section.
- [ ] A binary runs and matches its checksum:

  ```sh
  gh release download vX.Y.Z --pattern '*aarch64-apple-darwin*' --pattern SHA256SUMS
  shasum -a 256 --ignore-missing -c SHA256SUMS
  tar xzf watermelon-pgp-vX.Y.Z-aarch64-apple-darwin.tar.gz
  ./watermelon-pgp-vX.Y.Z-aarch64-apple-darwin/watermelon --version
  ```

- [ ] The image is on GHCR as `X.Y.Z` and `latest`, for amd64 and arm64:

  ```sh
  docker run --rm ghcr.io/tarannum22/watermelon-pgp:X.Y.Z --version
  docker buildx imagetools inspect ghcr.io/tarannum22/watermelon-pgp:latest
  ```

## 4. Homebrew tap

The `homebrew` job pushes the formula to
[tarannum22/homebrew-tap](https://github.com/tarannum22/homebrew-tap) only when the
`HOMEBREW_TAP_TOKEN` secret is set. It isn't yet, so the job prints the formula and warns, and
the tap is updated by hand:

- [ ] Generate the formula from the release's checksums and push it to the tap:

  ```sh
  test -d ../homebrew-tap || git clone https://github.com/tarannum22/homebrew-tap ../homebrew-tap
  gh release download vX.Y.Z --pattern SHA256SUMS --dir /tmp/wm-X.Y.Z
  packaging/homebrew/formula.sh X.Y.Z /tmp/wm-X.Y.Z/SHA256SUMS \
      > ../homebrew-tap/Formula/watermelon-pgp.rb
  cd ../homebrew-tap && git commit -am "watermelon-pgp X.Y.Z" && git push
  ```

- [ ] It installs: `brew update && brew upgrade tarannum22/tap/watermelon-pgp && watermelon --version`
      (`brew test` and `brew audit --strict tarannum22/tap/watermelon-pgp` for formula changes).

## 5. Website

Merge only once the release has its tarballs, or the install commands point at nothing. The
`Website` workflow (`pages.yml`) deploys `site/` when it changes on `main`.

- [ ] `site/index.html`: the version badge in the hero (`vX.Y.Z · <highlights> · open source`),
      `"softwareVersion"` in the structured data, and the tarball commands in Install
      (`watermelon-pgp-vX.Y.Z-*.tar.gz`).
- [ ] `site/sitemap.xml`: `<lastmod>` is the release date.
- [ ] If the UI changed: retake the screenshots in `site/img/` (`dashboard`, `jobs`, `job`,
      `audit-search`, `keys`, each also as `-dark.png`) from a demo installation in the released
      `ghcr.io/tarannum22/watermelon-pgp:X.Y.Z` image with made-up data, at 1280×809 CSS px ×
      1.25 = 1600×1011.
- [ ] If the dashboard changed: `site/img/social-card.png` (1200×630, the link preview) shows the
      new one.
- [ ] Features and FAQ on the site mention what's new.
- [ ] `python3 .github/scripts/check-branding.py site` passes.
