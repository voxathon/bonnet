# Releasing Bonnet

Publishing to PyPI is fully automated by
[.github/workflows/release.yml](.github/workflows/release.yml), triggered
by pushing a `v*` tag. It uses PyPI's trusted publishing (OIDC): GitHub
Actions proves its identity directly to PyPI at publish time, so there is
no API token to generate, store as a secret, or eventually leak.

## One-time setup

Do this once, before the first automated release. Both steps are dashboard
actions — nothing to run locally.

### 1. Register the trusted publisher on PyPI

1. Sign in at [pypi.org](https://pypi.org) with the account that owns the
   `bonnet` project.
2. Go to the `bonnet` project's **Settings** → **Publishing**.
3. Add a new trusted publisher with exactly these values:
   - **Owner**: `voxathon`
   - **Repository name**: `bonnet`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`

   All four must match the repo and workflow file exactly, or PyPI will
   reject the publish with an OIDC identity mismatch.

### 2. Create the GitHub environment

1. In the GitHub repo: **Settings** → **Environments** → **New environment**.
2. Name it `pypi` (must match the trusted publisher's environment name above).
3. Optional but recommended: add a required reviewer protection rule, so
   every publish needs a manual approval click in the Actions run before it
   goes out — a last chance to catch a bad tag.

Nothing else to configure. No secrets to add to this environment — trusted
publishing doesn't use one.

## Cutting a release

1. Bump the version in **both** places (the release workflow checks they
   match the tag and fails otherwise):
   - `pyproject.toml` — `version = "..."`
   - `src/bonnet/__init__.py` — `__version__ = "..."`
2. Update [CHANGELOG.md](CHANGELOG.md) with what changed.
3. Commit, then tag and push:
   ```sh
   git commit -am "release: v0.1.1"
   git tag v0.1.1
   git push origin main v0.1.1
   ```
4. Watch the **Release** workflow in the Actions tab. It verifies the
   version, runs the full test matrix on Linux and Windows, builds the
   wheel and sdist, publishes to PyPI, then creates a GitHub Release with
   the built artifacts attached and auto-generated release notes.

If the environment has a required reviewer, the run will pause before the
`publish-pypi` job and wait for approval — nothing reaches PyPI until then.

## If something goes wrong

- **Version mismatch caught by `verify-version`**: fix the version in
  whichever file is wrong, delete the tag locally and on the remote
  (`git tag -d v0.1.1 && git push origin :refs/tags/v0.1.1`), then retag.
- **Tests fail**: nothing was published. Fix the issue, retag with the same
  process — a failed run never reaches the publish step.
- **Publish succeeds but you find a bug immediately after**: PyPI does not
  allow re-uploading the same version. Cut a new patch version instead;
  don't try to delete or overwrite the release.
