# Pull-request builds

Every pull request is built in full by the [Build workflow](../.github/workflows/tooling.yml):
lint, host tests, and the same packaging a release gets. The result is an installable copy
of the app, kept for 14 days, that a reviewer can put on a console before merging.

## What a pull request produces

| | Pull request | Tag, or a run started by hand |
| --- | --- | --- |
| Artifact name | `<repository>-PR<number>-<commit>` | `ps5-native-app-boilerplate-<commit>` |
| `<commit>` | First seven characters of the pull request's own head commit | The commit built |
| Label inside the app | `PR <number>, <commit>` | None |
| `contentVersion` | Unchanged | Unchanged |

Two details are deliberate:

- **The commit is the pull request's head**, not `github.sha`. For a pull request,
  `github.sha` is a temporary merge commit that appears nowhere on the pull request's page,
  so an artifact named after it cannot be matched to what is being reviewed.
- **The version is not touched.** A test build reports the same `contentVersion` as the
  release it is based on, so the [update check](UPDATE_CHECK.md) and
  [self-update](SELF_UPDATE.md) behave exactly as they will after the merge. The label is
  a separate file.

## Getting the build

1. Open the pull request, then **Checks** and the **Build** run (or the run's page under
   **Actions**).
2. Download the artifact named `<repository>-PR<number>-<commit>` from the run's
   **Artifacts** list. GitHub requires a signed-in account for this.
3. Unpack it: it holds the app's ZIP and `SHA256SUMS`. Check the files with
   `sha256sum -c SHA256SUMS`, then install as described in [Deployment](DEPLOYMENT.md).

A first-time contributor's pull request does not build until a maintainer approves the
workflow run. That is GitHub's default for public repositories and is worth keeping: the
build runs the pull request's code.

## The label inside the app

`tools/build.sh` writes the environment variable `BUILD_LABEL` to `build-label.txt` at the
root of the app folder (`/app0/build-label.txt` on the console). The workflow sets it for
pull requests only. A build without it writes no file, so a release never carries one, and
an in-app update replaces the folder and with it the label.

`BUILD_LABEL` must be 1 to 40 characters from letters, digits, spaces and `, . _ # -`. The
build refuses anything else before compiling, so the text is safe to show as it is.

The skeleton shows the label at the bottom of its demo screen, in capitals because its
bitmap font has no lowercase:

```cpp
ps5::demo::read_asset_text("/app0/build-label.txt", std::span{build_label}, "");
```

In your own app, read the same file where you show the version, such as an About page, and
show nothing when it is missing. Do not put the label into `param.json` or compare it with
anything: it is for people.

The same works on your PC, for a build you want to tell apart on the console:

```bash
BUILD_LABEL="pacing test 2" make
```

## Using this in your project

`tools/init-project.sh` leaves the workflow as it is. The pull-request name follows the
repository's name by itself. The name used for tags and runs started by hand,
`ps5-native-app-boilerplate-<commit>`, appears twice in the workflow (the upload, and the
release job's download); rename both together if you want your project's name there.

Pull-request runs have a read-only token and no secrets, including for forks. Do not move
this build to `pull_request_target` to post links or comments: that event runs with write
access and secrets, and building a contributor's code under it hands both to that code.
