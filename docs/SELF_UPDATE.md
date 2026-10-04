# Self-update

An app listed on [homebrew.page](https://homebrew.page) can replace itself
with its newest release: it asks its user, downloads the release, and a small
helper program puts the new version in place once the app has closed. This
optional example is that feature: an engine you copy into your project, the
helper it ships with, and an example title.

It builds on the [update check](UPDATE_CHECK.md), which only tells the user
that a newer release exists. Use that one if telling is enough.

> **Status.** The whole flow is covered by host tests (the engine against the
> real helper code, with real archives and folders). **It has not yet been run
> on a console.** The points that only a console can show are listed under
> [What is not proven yet](#what-is-not-proven-yet).

## What the user sees

1. The app starts and checks the catalog in the background.
2. If a newer release is listed: **"Update available. Version 1.4.0. Update
   now / Later."**
3. On "Update now": a progress bar with the amount downloaded and the time
   left ("about 20 s left"), then the same for unpacking. It can be cancelled
   at any point; nothing has been changed yet.
4. "Updating. The app closes now." The app closes itself.
5. A few seconds later a system notification: **"My App was updated to 1.4.0.
   Open it again."**

If no payload loader is running on the console, step 3 fails at once with a
clear reason and the app is untouched; it can still tell the user about the
update, as the update check does.

## How it works

Two programs take part, and each does only what it can do well.

| | The app (sandboxed) | The helper (`self-updater.elf`) |
| --- | --- | --- |
| Runs | In its normal sandbox, as always | Outside the sandbox, started by the console's payload loader |
| Does | Asks the catalog and verifies it; asks the user; downloads the release over HTTPS; shows progress | Saves the download; checks and unpacks it; waits for the app to close; replaces the app's files; refreshes the home-screen copies; posts the notification |
| Why here | It has the screen and a working HTTPS client | An app can't write to its own folder, and the console slows an app's file writes to about 2 MB/s after a few hundred megabytes; a loader-started process has neither limit |

The app sends the helper to the payload loader on loopback port 9021, the same
way the loader receives any payload. The connection the helper was sent over
then carries their conversation
([`self_update_protocol.h`](../examples/self-update/self_update_protocol.h)):
the app streams the archive to the helper as it downloads it, the helper
reports its progress, and at the end the app says `apply` and closes.

The helper never elevates the app and never touches the kernel. It is an
ordinary program doing file work with the rights every payload has.

### The steps

1. **Check.** `self_update_check_self()` fetches the catalog's `manifest.json`
   and its signature, verifies the signature, then fetches the app's own file
   and requires its SHA-256 to be the one the manifest lists. Only then does it
   believe the release's address, size and SHA-256.
2. **Ask.** Your interface asks the user.
3. **Start.** `self_update_start()` starts the helper. The helper finds the
   app's installed folder, checks that it holds the version that is running,
   and makes its work folder on the same drive
   (`<drive>/self-update/<TITLEID>/`).
4. **Download.** The app downloads the ZIP from GitHub and streams it to the
   helper, hashing it on the way.
5. **Stage.** The helper checks size and SHA-256 again, validates the archive
   (paths, links, sizes, one app only) and unpacks it beside the app. The
   unpacked app must name the same title ID and the version the catalog
   listed.
6. **Apply.** `self_update_apply()` gives the go-ahead and the app closes
   itself. The helper waits until the app's sandbox is gone, then moves the
   app's files out and the new ones in (renames on the same drive), refreshes
   the console's copies of `sce_sys`, removes its work folder and posts the
   notification.

The app's folder itself stays where it is, so the console's existing mount of
it keeps pointing at the right place and the next launch reads the new files.

## Use it in your app

1. Copy the kits into your sources:

   ```bash
   cp examples/update-check/{update_check,console_curl}.{h,c} src/
   cp examples/self-update/self_update*.{h,c} src/
   ```

2. Build the helper and ship it in the app's folder, and link libcurl, in the
   `Makefile`:

   ```make
   PACBREW_PACKAGES += libcurl
   APP_WRAP_SYMBOLS += fcntl
   APP_ROOT_FILES += build/self-update/self-updater.elf

   app ffpkg ffpfsc packages: self-update-helper
   ```

   `make self-update-helper` builds `build/self-update/self-updater.elf` from
   [`examples/self-update-helper/`](../examples/self-update-helper) and checks
   that the loader will accept it. The helper is the same for every app: it
   takes the title ID from the request.

3. Keep `downloadDataSize` positive in `sce_sys/param.json` (the template's
   default): the kit keeps one number in `/download0`.

4. Drive it from your interface. Nothing here may run on the thread that
   draws, except `self_update_poll`:

   ```cpp
   #include "self_update.h"

   static self_update_offer offer;
   static self_update_job job;   // zero-initialised

   // On a worker thread, once per launch:
   if (self_update_check_self(&offer) == SELF_UPDATE_AVAILABLE)
       ask_user("Version %s is available. Update now?", offer.version);

   // When the user says yes:
   self_update_start(&job, self_update_console(), &offer);

   // Every frame while it runs:
   self_update_status status;
   self_update_poll(&job, &status);
   // status.phase, status.done, status.total, status.time_left, status.error
   if (status.phase == SELF_UPDATE_READY && self_update_apply(&job) == 1)
   {
       show("Updating. The app closes now.");
       sceSystemServiceLoadExec("exit", nullptr);   // close the app
   }

   // To cancel (any time before apply): self_update_cancel(&job);
   // After FAILED or CANCELLED: self_update_finish(&job);
   ```

5. Release as the catalog asks: a `.zip` of the app folder attached to a
   GitHub release, and a higher `contentVersion` in `sce_sys/param.json`
   ([App versions](https://github.com/blackbearreloaded/ps5-homebrew-catalog/blob/main/docs/versioning.md)).
   The helper is part of that ZIP, so each release carries its own.

### The states

| `status.phase` | Meaning | Show |
| --- | --- | --- |
| `SELF_UPDATE_STARTING` | Starting the helper | "Preparing" |
| `SELF_UPDATE_DOWNLOADING` | `done`/`total` are bytes of the archive | Progress, `time_left`, Cancel |
| `SELF_UPDATE_UNPACKING` | `done`/`total` are bytes unpacked | Progress, `time_left`, Cancel |
| `SELF_UPDATE_READY` | Staged. Call `self_update_apply()` or `self_update_cancel()` | |
| `SELF_UPDATE_APPLYING` | The helper has the go-ahead | "The app closes now", then close |
| `SELF_UPDATE_CANCELLED` | Stopped on request; nothing was changed | |
| `SELF_UPDATE_FAILED` | `error` says why; nothing was changed | The reason |

| `self_update_check_self()` | Meaning | What to do |
| --- | --- | --- |
| `SELF_UPDATE_AVAILABLE` | The offer is filled and verified | Ask the user |
| `SELF_UPDATE_UP_TO_DATE` | Nothing newer | Nothing |
| `SELF_UPDATE_UNKNOWN` | No answer, or the app isn't listed | Nothing |
| `SELF_UPDATE_UNTRUSTED` | The signature, the sequence or a hash didn't verify | Nothing; log it |
| `SELF_UPDATE_NOT_INSTALLABLE` | Newer, but not a ZIP on GitHub with a digest | Tell the user, as the update check does (`offer.version`, `offer.page`) |

### Rules

- **Always ask.** Never update without the user's yes, and never during
  something they would lose.
- **Never on the thread that draws**, except `self_update_poll`.
- **After `self_update_apply()` returns 1, close the app at once.** The helper
  waits two minutes for it; then it gives up, removes its work and says so in
  a notification.
- **One update at a time**, and one check at a time: the kit isn't reentrant.
- **Save the user's state before closing.** `/download0` isn't touched by an
  update; the app's own folder is replaced whole.

## What it needs on the console

| Need | Why | Without it |
| --- | --- | --- |
| A payload loader listening on port 9021 | It starts the helper | `SELF_UPDATE_FAILED`: "The update helper couldn't be started. Is the payload loader running?" Nothing is changed |
| The app installed as a **folder** in a usual place (`/data/homebrew`, `/data/etaHEN/games`, the same on `/mnt/ext0`, `/mnt/ext1`, `/mnt/usb0`-`7`, or an external drive's root) | The helper replaces files in that folder | "The app's folder wasn't found. Apps installed as an image can't update themselves" |
| Exactly one installed copy, at the running version | So the right files are replaced | A refusal that says which it was |
| Free space on the app's drive for the ZIP and the unpacked app together | Staging happens before anything is replaced | A refusal before the download, or before unpacking |
| The app listed in the catalog as a ZIP | The check | `SELF_UPDATE_UNKNOWN` or `SELF_UPDATE_NOT_INSTALLABLE` |

## Trust

Updating means installing code, so every link is checked:

| What | Checked by | Against |
| --- | --- | --- |
| The catalog's manifest | The app | An Ed25519 signature from one of the catalog's two keys, which the kit carries |
| A replayed old catalog | The app | The manifest's sequence number may never go below the highest one accepted (kept in `/download0/self-update-sequence`) |
| The app's own catalog file | The app | Its SHA-256 in the signed manifest |
| The download's source | The app | Only `https://github.com/`, and GitHub's own release file host after a redirect |
| The download | The app, then the helper again | The size and SHA-256 in the app's catalog file |
| The archive's contents | The helper | No absolute or parent paths, links, special files, encryption or duplicates; one app; bounded sizes |
| What was unpacked | The helper | `sce_sys/param.json` must name this title ID and the listed version |
| What is replaced | The helper | The one installed folder whose `param.json` names this title ID, at the running version |

HTTPS certificates are verified throughout (see [libcurl](CURL.md)). What the
kit does not defend against: the developer's own release being malicious, or
the developer's GitHub account being taken over before the catalog's update
is reviewed. The catalog lists exactly one file by its hash; a release asset
replaced afterwards no longer matches and is refused.

The helper is as powerful as any payload: whoever can reach the loader's port
can already run anything. It still refuses requests that aren't a title ID,
versions and a digest, and it writes only inside the app's folder, its own
work folder and the console's `sce_sys` copies for that title.

## If something goes wrong

| When | What happens |
| --- | --- |
| The download fails, doesn't match, or is cancelled | The helper removes its work folder. The app is untouched |
| The archive is refused, or isn't the listed version | The same |
| The app doesn't close within two minutes of `apply` | The helper removes its work and notifies: "wasn't updated: it didn't close" |
| A file can't be moved while replacing | The moves made so far are undone and the app is as it was; a notification says so |
| The console loses power **during** the replacement | The one unprotected moment: the app's folder may be incomplete, and the app must be installed again. The replacement is a handful of renames, a fraction of a second |
| The console loses power at any other time | A leftover `<drive>/self-update/<TITLEID>/` folder, removed by the next update attempt |

## The example title

`make self-update-example` builds `dist/PPSA99782/`, a title that checks
itself and draws the prompt and the progress with the template's CPU renderer
(Cross: update now; Circle: later, or cancel). It writes every step to the
kernel log and to `/download0/self-update.txt`, each line starting
`SELF-UPDATE:`.

Its title ID isn't in the catalog, so as built it reports "No update
information". Build definitions, for trying it and for scripted console runs:

| Definition | Effect |
| --- | --- |
| `SELF_UPDATE_RUN_TAG=<word>` | Printed in the first line, to tell runs apart |
| `SELF_UPDATE_DEV_OFFER` | **Development only.** Takes the offer from `/app0/assets/offer.txt` (five lines: new content version, version name, release ZIP on GitHub, SHA-256, size) instead of the catalog. It skips the catalog's signature: never ship a build with it |
| `SELF_UPDATE_AUTO_ACCEPT=<seconds>` | Accepts the offer after that long, as if Cross had been pressed |
| `SELF_UPDATE_EXIT_AFTER=<seconds>` | Closes the title that long after it has nothing more to do |

An app with a real interface draws its own prompt from the same values. For a
dialog and progress view in the style of ProsperoStore, see
[ps5-homebrew-ui](USER_INTERFACE.md).

## Tests

```bash
make test-self-update
```

Builds the engine and the helper's code into one host test, with the address
and undefined-behaviour sanitizers, and runs them against each other over a
socket pair with real ZIP archives and real folders:

- the check: a valid catalog, an old sequence, a bad or short signature, a
  changed app file, an app that isn't listed, a release that isn't a ZIP or
  isn't on GitHub;
- a whole update, including that nothing is replaced while the app's sandbox
  exists, and that the old files, the work folder and the console's `sce_sys`
  copies end up right;
- refusals: a download that doesn't match, a connection that drops, an archive
  holding another version or another app, an installed copy at another
  version, two installed copies, no payload loader;
- cancelling once staged, and an app that never closes;
- the replacement undone when a file can't be moved; SHA-256 against the
  standard's test values; the time-left wording; the address rules.

The host test replaces the network, the Ed25519 check and the payload loader.

## What is not proven yet

None of this has run on a console. A console run has to show:

1. a sandboxed app can start the helper through the loader on port 9021;
2. the helper keeps running after the app has closed;
3. the helper sees the app's sandbox (`/mnt/sandbox/<TITLEID>_000`) disappear;
4. files replaced inside the app's folder are what the next launch runs, with
   no wait for the folder to be mounted again;
5. the Ed25519 check through OpenSSL accepts the live catalog;
6. the download from GitHub's release host through its redirect, and its
   speed;
7. the frame loop added to the CPU renderer (`run_frames`) and controller
   input in the example.

## Credits

The archive validation, the file helpers and the loader-started worker come
from ProsperoStore, where they are used to install apps; the time-left wording
is its too. ZIP reading is [miniz](https://github.com/richgel999/miniz) (MIT),
vendored in `third_party/miniz`.
