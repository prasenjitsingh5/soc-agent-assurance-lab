# Release process

The package is published to PyPI as `soclab` by `.github/workflows/release.yml`. The workflow uses PyPI trusted publishing: PyPI accepts an OpenID Connect token from this repository, this workflow file and the `pypi` GitHub environment. No API token is stored anywhere. Each release also carries PEP 740 attestations signed with the same identity.

## One-time setup

Do this once before the first release. Both halves must match exactly or PyPI rejects the upload.

PyPI, under the project's publishing settings (for the very first release, add a pending publisher at https://pypi.org/manage/account/publishing/ instead; the project is created on first upload):

| Field | Value |
|---|---|
| PyPI project name | `soclab` |
| Owner | `prasenjitsingh5` |
| Repository name | `soc-agent-assurance-lab` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

GitHub, under Settings, Environments: create an environment named `pypi`. Add the repository owner as a required reviewer so every publish waits for one click, and restrict deployment branches and tags to tags matching `v*`.

## Cutting a release

1. Confirm `main` is green: `make verify`, plus the `ci` and `security` workflows on the merge commit.
2. Bump the version. `pyproject.toml` is the single source; `soclab.__version__` reads it from the installed metadata.

   ```bash
   uv version 0.2.0
   uv lock
   uv sync --extra dev
   uv run soclab version
   ```

3. Update `CHANGELOG.md`: rename `[Unreleased]` to the version and date, start a new empty `[Unreleased]` section. Add `docs/releases/<version>-evidence.md` with the verification record, as `0.1.0-evidence.md` does.
4. Open a pull request titled `chore(release): 0.2.0`, let CI pass, squash-merge.
5. Tag the merge commit. The tag must be `v` plus the package version; the workflow refuses anything else.

   ```bash
   git checkout main && git pull
   git tag -a v0.2.0 -m "soclab 0.2.0"
   git push origin v0.2.0
   ```

6. Publish a GitHub release for the tag. Use the changelog section as the notes.

   ```bash
   gh release create v0.2.0 --title "soclab 0.2.0" --notes-file notes.md
   ```

   Publishing the release starts the workflow. A draft release does not.

7. Watch the workflow. It has three jobs:
   - `build`: checks the tag against `pyproject.toml`, runs `uv build`, installs the wheel into an empty virtual environment and runs `soclab version`, `soclab scenarios` and `soclab demo --help` from a directory outside the checkout, writes a CycloneDX SBOM of that environment, and uploads `dist` and `sbom` as artifacts.
   - `publish`: waits for the `pypi` environment approval, then uploads `dist/` with `pypa/gh-action-pypi-publish` and attestations enabled.
   - `test-install`: on a clean runner, installs `soclab==<version>` from PyPI (retrying while the index catches up) and runs `soclab --help`, `soclab demo --help`, `soclab version` and `soclab scenarios`.

8. Verify on PyPI. Open https://pypi.org/project/soclab/. The new version should list both files with a verified publisher and attestation badges. Then, from any machine:

   ```bash
   uvx soclab@0.2.0 version
   ```

9. Attach the SBOM to the GitHub release. Download the `sbom` artifact from the workflow run and upload both files.

   ```bash
   gh run download <run-id> --name sbom --dir sbom
   gh release upload v0.2.0 sbom/soclab-0.2.0.cdx.json sbom/soclab-0.2.0.cdx.json.sha256
   ```

## Re-running and rolling back

- The workflow can be started by hand from the Actions tab. Choose the tag as the ref; a branch ref fails the tag check on purpose.
- PyPI never accepts a file name twice. If `publish` succeeded and something later is wrong, do not delete the release. Fix forward with a new patch version.
- A broken version can be yanked on PyPI. Yanking hides it from resolvers that do not pin it and leaves pinned installs working.
- If OPA moves to a new version, update `OPA_VERSION` and every digest in `soclab/policy/opa_binary.py` together, from the `.sha256` files on the OPA release page, and bump `OPA_VERSION` in `ci.yml` and the image tag in `docker-compose.yml`.
