# Packaging & distribution

`mytools-osint` ships through multiple channels. **Phase-1** (PyPI, GitHub
Releases binaries, .deb/.rpm/AppImage, Homebrew tap, Docker on ghcr.io) are
the always-on channels — anything pushed as a `v*` tag goes here. **Phase-2**
(Winget, Scoop) have manifests staged in this directory and need a manual
PR/bucket-update after each release.

## Quick reference — install commands

| Channel    | Command |
|------------|---------|
| Homebrew   | `brew tap Azizbek16l/osint && brew install mytools-osint` |
| pipx       | `pipx install mytools-osint` |
| Scoop      | `scoop bucket add bluetm https://github.com/Azizbek16l/scoop-bucket && scoop install mytools-osint` |
| Winget     | `winget install Bluetm.MytoolsOsint` |
| apt        | `sudo apt install ./mytools-osint_0.2.0_amd64.deb` (download from Releases first) |
| dnf/yum    | `sudo dnf install https://github.com/Azizbek16l/mytools-osint/releases/download/v0.2.0/mytools-osint-0.2.0-1.x86_64.rpm` |
| AppImage   | `curl -L .../mytools-osint-0.2.0-x86_64.AppImage -o osint && chmod +x osint` |
| Docker     | `docker run --rm ghcr.io/azizbek16l/osint:latest torvalds` |
| Direct bin | `curl -L .../osint-linux-x86_64 -o osint && chmod +x osint && sudo mv osint /usr/local/bin/` |

## Phase 1 — ship today

### PyPI (universal)
```
pipx install mytools-osint            # CLI only
pipx install "mytools-osint[gui]"     # CLI + Qt GUI
```
- Source of truth: `pyproject.toml` (hatchling backend)
- Build: `python -m build`
- Publish: `twine upload dist/*` or via the `release.yml` workflow (Trusted Publishing / OIDC)

### GitHub Releases (binaries)
- Workflow: `.github/workflows/release.yml`
- Triggered by `git tag v*` push
- Builds Windows x64, macOS Intel + Apple Silicon, Linux x86_64 in parallel
- Uploads `osint-<target>` and `mytools-osint-<target>` plus SHA256SUMS
- Direct install:
  ```
  curl -L https://github.com/Azizbek16l/mytools-osint/releases/latest/download/osint-linux-x86_64 -o osint
  chmod +x osint
  ```

### Homebrew tap (macOS + Linux Brew)
- Tap repo: `github.com/Azizbek16l/homebrew-osint`
- Formula: `packaging/homebrew/Formula/mytools-osint.rb` (copy into the tap repo)
- Update SHAs after every release; can be automated with `brew bump-formula-pr`
- Usage:
  ```
  brew tap Azizbek16l/osint
  brew install mytools-osint
  ```

## Phase 2 — when ready

### Winget (Windows 11)
- Stage manifest: `packaging/winget/Bluetm.MytoolsOsint.installer.yaml`
- Add the `.locale.en-US.yaml` and root `.yaml` per the [winget-pkgs schema](https://github.com/microsoft/winget-pkgs#authoring-manifests)
- Submit to `microsoft/winget-pkgs` (manifests/b/Bluetm/MytoolsOsint/0.1.0/)
- Automate with `wingetcreate update` in CI

### Scoop (Windows, no-admin)
- Bucket repo: `github.com/Azizbek16l/scoop-bucket`
- Manifest: `packaging/scoop/mytools-osint.json`
- `persist` directory keeps the Telethon `.session` across upgrades
- Usage:
  ```
  scoop bucket add bluetm https://github.com/Azizbek16l/scoop-bucket
  scoop install mytools-osint
  ```

### Docker (SecOps / CI)
- `Dockerfile` at repo root (multi-arch via Buildx)
- Image: `ghcr.io/Azizbek16l/osint:latest`
- Usage:
  ```
  docker run --rm ghcr.io/Azizbek16l/osint:latest torvalds
  ```

### npm wrapper (cross-platform via npx)
- TODO: create `@Azizbek16l/mytools-osint` package with `postinstall.js` that
  downloads the right binary from GitHub Releases, plus `@Azizbek16l/osint-<plat>-<arch>`
  optionalDependencies (the esbuild/sentry-cli pattern).

### Linux native (AppImage / .deb)
- AppImage wrapper: TODO `scripts/make_appimage.sh`
- .deb / .rpm: build with `fpm -s dir -t deb` after Phase-1 is stable

## Updater story

| Channel | Update command |
|---|---|
| PyPI | `pipx upgrade mytools-osint` |
| Homebrew | `brew upgrade` |
| Winget | `winget upgrade Bluetm.MytoolsOsint` |
| Scoop | `scoop update mytools-osint` |
| Docker | `docker pull ghcr.io/Azizbek16l/osint:latest` |
| AppImage / direct | `osint self-update` (planned) |

## Release runbook

1. Edit `pyproject.toml` → bump `version`.
2. Update `CHANGELOG.md` → move `[Unreleased]` to `[X.Y.Z]` with the date.
3. Commit + tag:
   ```
   git commit -am "release: vX.Y.Z"
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin main vX.Y.Z
   ```
4. The `release.yml` workflow fires on the tag. Wait for green.
5. Update Homebrew formula with the released SHAs (or use `brew bump-formula-pr`).
6. Update winget/scoop manifests with the released SHAs.
