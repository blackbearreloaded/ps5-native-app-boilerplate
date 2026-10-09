# Build output and release ZIP

Every application build creates and validates `dist/<TITLE_ID>/` and archives
it as `dist/<TITLE_ID>.zip`. The folder and its ZIP are the only outputs; on
Windows, `./build.ps1` runs the same build through WSL.

Tagged GitHub Releases and every CI build attach a ZIP of the validated
directory-style application and its `SHA256SUMS`, and nothing else.

```bash
make app
```

The release workflow uses Python's standard-library `zipfile` module to archive
`dist/<TITLE_ID>/` as `<TITLE_ID>.zip`. The ZIP is a distribution convenience,
not another console filesystem format; extract it before directory deployment.
Every entry is stored with permissions `0777` (`tools/zip-open-modes.py`): the console only
starts an app whose files are open to every user, and some tools keep a ZIP's permissions when
they unpack it.

Once the ZIP is final, the workflow signs a build-provenance attestation for it (the
`Attest the release ZIP` step, `actions/attest`): a record, kept by GitHub, that this exact
file was built by this workflow from this commit. The step runs under two conditions: the run
is not a pull request (a fork's run cannot sign), and the repository is public (attestations
in a private repository need a plan that includes them). The build job holds `id-token: write`
and `attestations: write` for this step alone. The release publishes the same file, so nothing
is attached to it: the attestation is found by the file's hash. Anyone can check a downloaded
ZIP with the GitHub CLI:

```bash
gh attestation verify <TITLE_ID>.zip -R <owner>/<repository>
```

Only builds made by the workflow since this step was added are covered; an older release, or
a ZIP built on a PC, has no attestation and the command says so.

## Publishing a release

A release is made by pushing the version tag: the workflow builds, attests and publishes the
ZIP and `SHA256SUMS`. Release files are not attached by hand, so that every published file
comes from a run and has an attestation. The publish step handles three cases:

- **No release for the tag:** it creates one with the two files.
- **A release without a ZIP** (notes written in advance, or a draft): it adds the two files
  and leaves the title and notes alone.
- **A release that already has a ZIP:** nothing is replaced or deleted, because the catalog
  at homebrew.page records each release ZIP's checksum and the store refuses a file that
  differs. The run ends green with a warning that those files were not published by it and
  may have no attestation.
