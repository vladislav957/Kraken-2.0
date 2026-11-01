# Installing Kraken Audit

Two ways to run the toolkit. Pick one.

| | Needs Python? | Best for |
| --- | --- | --- |
| **A. Standalone binary** | **No** — nothing but the binary | end users, locked-down boxes, "just give me something I can run" |
| **B. From source** | Yes (Python 3.10+, stdlib only) | developers, auditing/modifying the code |

Everything here is **defensive and read-only** — see [COMPLIANCE.md](./COMPLIANCE.md).

---

## A. Standalone binary — no Python required

The whole toolkit (every CLI auditor **and** the desktop app) is packaged into
a single self-contained executable called `kraken`. The machine that runs it
needs **no Python, no pip, no Tk — nothing installed.**

### Run it

```bash
chmod +x kraken
./kraken                 # launch the desktop app (GUI)
./kraken --help          # list all commands
./kraken exposure        # audit what of THIS host is reachable off-box
./kraken node  --conf ~/.bitcoin/bitcoin.conf
./kraken miner --target 192.168.1.50
./kraken report --node ~/.bitcoin/bitcoin.conf --exposure --output report.md
```

### Install it system-wide (optional)

```bash
sudo install -m 0755 kraken /usr/local/bin/kraken
kraken --help            # now runnable from anywhere
```

### Where the binary comes from

A binary is specific to one OS and CPU architecture (e.g. Linux x86-64). Build
it once on a machine of that type — you only need Python **to build**, never to
run:

```bash
git clone -b claude/amazing-turing-qerm47 https://github.com/vladislav957/Kraken-2.0.git
cd Kraken-2.0
./packaging/build.sh
# -> dist/kraken      (copy this single file to any machine of the same OS/arch)
```

`build.sh` creates a throwaway virtualenv, installs
[PyInstaller](https://pyinstaller.org/) into it, and freezes the app. The
`dist/kraken` it produces carries its own Python runtime and Tk libraries
inside, so the target box needs none of them.

> **Build requirements:** a Python 3.10+ that can `import tkinter` (so the GUI
> is bundled), and one-time internet access to fetch PyInstaller. On Debian /
> Ubuntu: `sudo apt install python3 python3-venv python3-tk`.

> **Note:** Build on the oldest OS you need to support — a binary built on a
> newer glibc may not run on older ones. Build separately for each target
> (Linux x86-64, Linux arm64, macOS, …); binaries are not cross-platform.

### Windows (`kraken.exe`)

PyInstaller is **not** a cross-compiler — a Windows `.exe` must be built **on
Windows**. Two ways to get one:

- **Download it** — once a `v*` tag is pushed, GitHub Actions builds
  `kraken-windows-x86_64.exe` and attaches it to the
  [Releases](https://github.com/vladislav957/Kraken-2.0/releases) page. Grab it,
  then double-click, or from a terminal:

  ```powershell
  .\kraken.exe --help
  .\kraken.exe exposure
  .\kraken.exe node --conf $env:APPDATA\Bitcoin\bitcoin.conf
  ```

- **Build it yourself** — on a Windows PC with
  [Python 3.10+](https://www.python.org/downloads/windows/) (the installer
  bundles Tk):

  ```powershell
  git clone -b claude/amazing-turing-qerm47 https://github.com/vladislav957/Kraken-2.0.git
  cd Kraken-2.0
  powershell -ExecutionPolicy Bypass -File packaging\build.ps1
  # -> dist\kraken.exe
  ```

> The `.exe` is a console app that also opens the GUI window — run it from
> `cmd`/PowerShell for the CLI, or double-click it to open the desktop app.

### Prebuilt downloads for every OS (GitHub Releases)

You don't have to build anything yourself. The
[`build-binaries`](./.github/workflows/build.yml) workflow builds Linux,
Windows and macOS binaries on GitHub's runners:

- **On demand:** Actions tab → *build-binaries* → *Run workflow* → download the
  artifacts.
- **On a release:** push a tag and the binaries are attached to the Release:

  ```bash
  git tag v1.0.0 && git push origin v1.0.0
  ```

---

## B. From source — the classic way (needs Python)

The code is pure Python standard library — **no pip install, no dependencies.**

```bash
# Debian / Ubuntu: Python + Tk (for the GUI) + git + ss (for socket checks)
sudo apt install python3 python3-tk git iproute2

git clone -b claude/amazing-turing-qerm47 https://github.com/vladislav957/Kraken-2.0.git
cd Kraken-2.0

python3 kraken_app.py                       # desktop app
python3 node_audit.py --conf ~/.bitcoin/bitcoin.conf
python3 kraken_report.py --exposure --output report.md
./run-tests.sh                              # 63 unit tests, no network
```

If Tk is missing you'll see a hint to `sudo apt install python3-tk`; the CLI
tools work without it.

---

## Verify it works

```bash
./kraken exposure          # or: python3 exposure_audit.py
```

You should get a findings list (or an `INFO` line if `ss`/`netstat` isn't
installed). Point the auditors only at infrastructure **you own or are
authorized to test**.
