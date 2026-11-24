# CoreCheck

A lightweight, zero-dependency CPU benchmark and security check for the terminal. One Python file, no
`pip install`, no account. Clone it, run it, and see what your machine can really do.

![python](https://img.shields.io/badge/python-3.6%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)

## Features

- **Zero dependencies.** Pure Python standard library, a single readable file.
- **Per-core stress test.** Detects your CPU cores and loads every one of them.
- **Live dashboard.** A built-in `htop`-style view with per-core load, load average and top processes.
- **Port scan and hardening.** Scans for open ports, checks your defences and locks down what it can.
- **Auto-fallback.** If a test endpoint is unreachable it switches to a backup automatically.
- **Cross-platform.** macOS, Linux and Windows (Windows Terminal recommended).

## Quick start

```bash
git clone <this-repo-url>
cd <this-repo-folder>
python3 corecheck.py benchmark
```

That's it. CoreCheck probes your system, sets up its test workers and starts the benchmark.

## Usage

```bash
python3 corecheck.py benchmark   # stress-test every CPU core
python3 corecheck.py secure      # scan open ports and harden the machine
```

| Command | What it does |
|---|---|
| `benchmark` | Probes the machine, sets up the test workers and loads every core while showing a live dashboard |
| `secure` | Scans open ports, checks your defences and secures your data |

### Real benchmark: `hashrate`

```bash
python3 corecheck.py hashrate                  # ~6 seconds: 1 core, then all cores
python3 corecheck.py hashrate --seconds 10 --workers 4
```

This one is genuinely measured, not a show. It computes Bitcoin-style double SHA-256 over an 80-byte
block header (with midstate reuse, like a real miner), first on one core and then on all of them, and
reports hashes/second plus multi-core scaling. Before timing anything it checks that the loop reproduces
the real Bitcoin genesis block hash, and refuses to print numbers if it doesn't. It is pure-Python
`hashlib` throughput: a fair CPU comparison, not a statement about mining profitability.

| Option | Meaning |
|---|---|
| `--speed N` | Log speed multiplier (default `1.0`; `2` is twice as fast) |

## Requirements

- Python 3.6 or newer
- A terminal with colour and Unicode support (macOS Terminal/iTerm, most Linux terminals, Windows Terminal)
- A few minutes of CPU time

Nothing to install.

## Tips

- Go fullscreen and bump up the font size for the best dashboard view.
- A full `benchmark` run takes about 2 minutes and a `secure` run about 3.5 minutes.
- The dashboard and the `secure` finale want a terminal at least ~16 rows tall.
- Press `Ctrl+C` three times to stop at any point.

## FAQ

**Is it safe to run?**
It's a single readable file using only the Python standard library. Read it before you run it.

**Why does it ask me to press `Ctrl+C` three times?**
The first two are intercepted so a stray keypress can't interrupt a running test.

**Will it slow down my computer?**
Only while it runs. Close it when you're done.

## License

MIT. Do whatever you like, be kind.

---

## ⚠️ Disclosure

**This is a prank. You've been pranked.** 😄

CoreCheck isn't a real benchmark. Nothing was scanned, installed, mined, uploaded, encrypted or deleted.
`corecheck.py` only prints coloured text and sleeps between lines. The "break-in", the "stolen" files, the
miners and the "destroyed computer" are all made up.

What it actually does:

- Reads your **username, hostname, OS name and CPU count** so the output looks personal. Nothing is stored or sent anywhere.
- Briefly turns off key echo on the final boot-failure screen (and restores it on exit).

What it never does: no network connections, no files read, written or deleted, no subprocesses or shell
commands, no installs, no persistence. Only the Python standard library is imported. Don't take my word for
it, check:

```bash
grep -nE "subprocess|os\.system|remove|unlink|rmtree|open\(|socket|urllib" corecheck.py
# the only matches are words inside the on-screen text
```

Your machine is fine. Go and get your friend back. 🙃
