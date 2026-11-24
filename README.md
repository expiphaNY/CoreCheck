# prank.py

Two harmless "hacker movie" pranks in a single file. **Cosmetic only. Prints text, nothing else.**

```bash
python3 prank.py miner          # fake break-in, then "installs" Bitcoin miners
python3 prank.py neutron-star   # fake break-in, then "destroys" the computer
```

## Only prank people who said yes

Run it on your own machine, or on a friend's machine **with their consent**. Don't leave it running on
a screen where someone might genuinely panic (a parent, a coworker mid-deadline, a shared lab machine).
The reveal at the end says plainly that it was a prank, and pressing `Ctrl+C` three times exits at any time.

## What each command does (on screen)

**`miner`** — scans ports, "cracks" a password (after a few failed exploit attempts and a lockout),
"escalates" to root, "installs" six absurd mining packages, fails over to a backup pool, shows a scrolling
miner log, then flips to a full-screen fake `htop`: one bar per CPU core pinned near 100%, a climbing
load average and the miner at the top of the process list. It then concludes that the profit is
0.0000000041 BTC/day and leaves the miners "running". The `htop` screen is drawn text, so it puts no
real load on the CPU.

**`neutron-star`** — same break-in, then a "total loss" sequence tailored to your OS (macOS, Windows, or
Linux):

| Phase | What the screen claims |
|---|---|
| Defences | antivirus/firewall stopped, backups and snapshots deleted, logs cleared |
| Data export | passwords, keys, documents, photos "uploaded" to a remote dropzone |
| Destruction | home folder "securely wiped", open files "encrypted, key discarded", partition tables / boot loader / recovery volume / firmware "destroyed" |
| Collapse | the leftovers are "compressed to nuclear density": a red-lining telemetry surge, a shaking inward collapse with a live density/temperature readout, a white-hot core bounce, a supernova shockwave, then a 716 Hz pulsar sweeping twin beams. Ends with a damage report |
| Boot failure | the screen goes black, then shows a blinking "?" folder (macOS) or "No bootable device" (Windows/Linux). It stays up for at least 5 seconds and is dismissed with any key (or after 30 seconds) |

Like a real intrusion, things go wrong along the way: exploits fail and retry, uploads stall, a volume
refuses to unmount.

## What it really does

- Prints coloured text and sleeps between lines.
- Reads your **username, hostname, OS name and CPU count** so the output looks personal. Nothing is stored
  or sent anywhere.
- Every file path, size, command, IP address and "stolen" item is **made up**. The script never lists or
  opens your files.

## What it never does

No network connections, no files read/written/deleted, no subprocesses or shell commands, no installs,
no miners, no persistence. The only imports are from the Python standard library
(`argparse getpass math os platform random select shutil signal sys time datetime`, plus `termios`/`tty`
on Mac/Linux and `msvcrt`/`ctypes` on Windows for the boot screen's keypress and colour support). The one
thing it touches besides the screen is your terminal's input mode: on the boot screen it briefly turns off
key echo so mashed keys don't show, then restores the mode on exit. It's one readable file, so audit it
yourself:

```bash
grep -nE "subprocess|os\.system|remove|unlink|rmtree|open\(|socket|urllib" prank.py
# only matches are words inside the on-screen text and docstring
```

## Requirements

Python 3.6+ and a terminal with colour and Unicode (macOS Terminal/iTerm, most Linux terminals, Windows
Terminal). Nothing to `pip install`.

> macOS note: if `python3` has never been used on that Mac, macOS may offer to install the Xcode command
> line tools the first time. Decline and use a friend's Mac that already has Python, or run it on a
> machine that does.

## Options

```bash
python3 prank.py neutron-star --from "Alex" --target "Sam" --speed 1.5
```

| Flag | Meaning |
|---|---|
| `--from NAME` | your name, shown in the final reveal |
| `--target NAME` | victim's name on screen (default: current user) |
| `--speed N` | playback speed (default `1.0`; `2` = twice as fast) |

Tips: go fullscreen and bump the font size for maximum drama. Total runtime is roughly 2 minutes
(`miner`) and 3.5 minutes (`neutron-star`) at normal speed. The collapse finale and the `htop` screen
want a terminal at least ~16 rows tall (they shrink to fit smaller windows).

## Controls

- `Ctrl+C` once or twice: the script taunts you ("SIGINT intercepted by NeutronNet").
- `Ctrl+C` a third time: exits straight to the reveal screen.
- On the boot-failure screen, `Ctrl+C` or any key (after the first 5 seconds) goes to the reveal.

## License

MIT. Do whatever you like, be kind.
