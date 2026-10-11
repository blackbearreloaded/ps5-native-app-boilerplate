# HDR, VRR and the black second at launch

What two fields of `sce_sys/param.json` tell the console about your app's
picture, why a wrong pair shows one or two seconds of black every time the app
opens, and which values to use. Everything here was observed on consoles with
our own apps; none of it comes from official documentation, and the meaning of
the bits is the community's reading of them.

## The short version

| Your app | `attribute` | `attribute3` |
| --- | --- | --- |
| A menu, a tool, a player, a 60 Hz game (the template's default) | `1644167168` (`0x62000000`) | `1048576` (`0x100000`) |
| A game or a stream whose frame rate really varies, or that outputs 120 Hz | `1644167168` (`0x62000000`) | `262208` (`0x40040`) or `524352` (`0x80040`), see below |

The first row opens without a black screen. The second row buys variable
refresh at the price of the black second.

## What happens with `0` and `0`

A game-category title with `attribute` `0` and `attribute3` `0` declares
nothing. On a console with a VRR television where **VRR** is on with *apply to
unsupported games*, and **HDR** is set to *on when supported*, the console then
decides for the title: no HDR, VRR forced. When the app starts it mutes the
output, sets a new video mode and unmutes it, and does the same again when the
app closes. The television shows black for one or two seconds each time.

The console's kernel log shows it. With `0` / `0`:

```text
[AvControl] -- app[0](appid=0xa017 attr=0x42e0057)(GAME RUNNING)(HDR:x HFR:x VR:x VRR:Boost)
[AvControl] ** mute(0) **
[AvControl] ** set_mode(0) ** -1/-1
[AvControl] ** unmute(0) **
[AvControl] App Event[POST_BEGIN]: elapse 1791[ms]
```

With `0x62000000` / `0x100000`:

```text
[AvControl] -- app[0](appid=0xc017 attr=0x2e0197)(GAME RUNNING)(HDR:o HFR:x VR:x VRR:x)
[AvControl] App Event[POST_BEGIN]: elapse 0[ms]
```

`POST_BEGIN: elapse` is the measure: the milliseconds the output was blanked.

Both fields are needed. With only the VRR bit the output still went from HDR to
SDR (1,788 ms). With only the HDR attribute the black second stays as soon as
VRR is switched on in the console's settings: a test made with VRR off will
look fixed and is not.

## The bits

| Field | Value | Meaning as observed |
| --- | --- | --- |
| `attribute` | `0x62000000` | The title is listed as `HDR:o`: the console keeps its HDR output mode. An app that draws SDR still looks right; the console maps it. |
| `attribute3` | `0x40` | 120 Hz output may be requested. |
| `attribute3` | `0x40000` | VRR supported. |
| `attribute3` | `0x80000` | "VRR at 120 Hz", used by newer titles instead of `0x40000`. |
| `attribute3` | `0x100000` | VRR off for this title. |

Combinations seen in use: `0x40040` (120 Hz and VRR), `0x80040` (120 Hz with
the newer VRR bit).

## Declaring VRR is a trade

A title that declares VRR support (`0x40040` or `0x80040`) is listed as VRR
capable, and the console switches the output for it at launch. With VRR on in
the console's settings that switch is the same black second. We found no value
that gives both: variable refresh while the app runs, and no blanking when it
opens.

So declare it only when it pays:

- **Worth it:** an emulator or a game whose frame rate moves between 30 and 60
  or dips under load, a game with a 120 Hz mode, a game stream whose rate comes
  from another machine.
- **Not worth it:** anything that draws a steady 60: menus, stores, tools,
  board games, radio and video players. Video has a fixed frame rate, and on
  some televisions variable refresh adds brightness flicker when the rate
  changes.

## Differences between system software versions

- **6.02** does not know `0x100000`. It logs `unknown vrr parameter(0x100000)`
  and leaves VRR off, which is the wanted result.
- **6.02** rejects `0x80040` and `0xC0040` the same way, and then VRR stays
  off; `0x40040` is accepted there and gives `VRR:TypeA`. A 13.60 console
  accepted `0x80040`. One value may not suit every console: read the log.
- Without the 120 Hz bit the console refuses a 120 Hz output request.

## Things that cost us time

- **The console reads these two fields from the installed folder at every
  launch.** Replacing `sce_sys/param.json` in the app's folder is enough to try
  a value; the app does not have to be registered again. (Other metadata, such
  as the name and the icon, is copied at registration and does need it.)
- **Test with VRR switched on in the console's settings**, and with HDR set to
  *on when supported*. With VRR off, half of the problem is hidden.
- **Read the log before changing settings.** The `[AvControl]` lines say what
  the console decided for the title (`HDR:o/x`, `VRR:x`, `VRR:Boost`,
  `VRR:TypeA`) and how long it blanked the output.
- **`sceVideoOutVrrUnpegFromFixedRate` returning `0x8029001c` means "already
  released"**, not "unavailable": opening the video port releases the rate by
  itself. The matching peg call returns the same code when nothing was pegged,
  and also for an app that left its sandbox, which the console then treats as a
  system process.
- **Media-category titles** (`applicationCategoryType` `65536`) were not
  measured separately. We set the same two values there.

## Checking your own app

1. Record the kernel log while the app starts (the loader's log port, or
   `klog` over the network).
2. Find the `[AvControl] -- app[0]` line for your title and the
   `App Event[POST_BEGIN]: elapse` line after it.
3. `elapse 0[ms]` and no `mute` / `set_mode` / `unmute` between them: no
   blanking. Anything in the hundreds or thousands: the output mode changed.
