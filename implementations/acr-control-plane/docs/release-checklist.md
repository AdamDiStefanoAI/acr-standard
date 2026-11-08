# Release packaging checks

Run these checks **before publishing**, not as a release-note caveat afterward.
The authoritative release workflow is
`.github/workflows/acr-control-plane-release.yml` at the repository root.
The historical workflow under this implementation's `.github/` directory is
not an active GitHub Actions workflow in this monorepo.

## Project license

- Keep the implementation `LICENSE` as the complete repository-root Apache 2.0
  license plus the existing ACR Framework Contributors notice. Do not abbreviate
  the license text or change its terms.
- Both published images, gateway and killswitch, must contain identical source
  license bytes at `/app/LICENSE` and in the installed Python distribution's
  `.dist-info/licenses/LICENSE`.
- The wheel and source distribution must also contain those exact license bytes.
  This checks the project's license, not every third-party dependency's notices.

From `implementations/acr-control-plane`, with Python 3.12, the `build` package,
and Docker available:

```bash
python scripts/test_release_licenses.py
python -m build --outdir dist
docker build --build-arg SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0+validation -t acr-gateway:license-check .
docker build --build-arg SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0+validation -f Dockerfile.killswitch -t acr-killswitch:license-check .
python scripts/check_release_licenses.py --dist-dir dist \
  --image acr-gateway:license-check --image acr-killswitch:license-check
```

Use a clean checkout and an empty `dist` directory. The check rejects missing,
changed, duplicate, or stale distribution artifacts. Image probes run only Python,
as the image's configured user and without networking; they do not start a gateway,
connect to production, or execute agent actions.

## Publication gate

1. Review the exact source revision and run the applicable CI, independent review,
   and newcomer checks. A packaging pass is not full ACR conformance or permission
   to release.
2. Run the release workflow's validation jobs on the PR or with **Run workflow**.
   A manual run only validates; it never publishes. Both images are built, checked,
   saved, reloaded and checked again. The wheel and source distribution are checked.
3. After release approval, publish a new version tag. Every publisher waits for
   both image validations and the Python distribution validation. A failing check
   blocks container, PyPI and compliance publication.
4. Publishers download and recheck the validated artifacts. Images and Python
   distributions are published without rebuilding. Container signatures and
   GitHub build-provenance attestations remain required. The Docker archive path
   uses the runtime image manifest with a separate provenance attestation, rather
   than a Buildx-generated provenance index.
5. Check all publication jobs, published artifact bytes, signatures and provenance
   before describing the release as complete. The GitHub Release waits for PyPI,
   both container publishers and the compliance package.

The v1.3.0 artifacts predate this fix. A source change alone does not repair them.
Use a new patch version for corrected artifacts; do not silently move the v1.3.0
tag or overwrite its published images. This process does not deploy to production.
