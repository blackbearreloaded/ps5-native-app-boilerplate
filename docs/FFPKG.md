# Build output formats

Every application or package build creates and validates
`dist/<TITLE_ID>/`. The Make targets map to the same PowerShell
`-OutputFormat` selections:

Tagged GitHub Releases and every CI build attach a ZIP of the validated
directory-style application and its `SHA256SUMS`, and nothing else.

| Make target / selection | Additional output | Packaging tool |
| --- | --- | --- |
| `make app` / `Folder` | None | None |
| `make ffpkg` / `Ffpkg` | `dist/<TITLE_ID>.ffpkg` | UFS2Tool |

```bash
make app
make ffpkg
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

`-Ffpkg` remains accepted as a compatibility alias for
`-OutputFormat Ffpkg` in the Windows PowerShell frontend.

## UFS2 FFPKG

The `.ffpkg` option creates and checks an uncompressed UFS2 filesystem image:

```text
ufs2tool makefs -S 4096 -b 20% -t ffs \
  -o version=2,bsize=32768,fsize=4096,minfree=0,softupdates=0,optimization=space \
  <title.ffpkg> <app-directory>
```

On first use, `tools/setup-packaging-dependencies.sh` or the equivalent
PowerShell bootstrapper fetches
[SvenGDK/UFS2Tool](https://github.com/SvenGDK/UFS2Tool) at commit
`b5307a60d5b4e3a68ba680e0e33cfadf05017c77`, builds its CLI with the .NET SDK
8 or newer, and caches it under ignored `.deps/UFS2Tool/`. The repository does
not distribute UFS2Tool source or binaries. The build reserves allocation
slack and verifies the resulting UFS2 superblock magic.

The same UFS2Tool-generated image was mounted through ShadowMountPlus and
launched successfully on PS5 system software 6.02 and 12.70.

Despite the similar names, `.ffpkg` here is a mountable filesystem image. This
project does not create a signed retail PKG/FPKG container.

Package files from older builds are not automatically deleted when a different
format is selected. Rebuild the exact format immediately before deployment so
an old image is not mistaken for the current app.
