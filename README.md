# Arazim Local

## Goals

- Understand the G2 network structure
- Find communication primitives
- Build a local website on G2

## Repository structure

- `./wiki/drive` — contains a URL to a Google Drive with explanations
- `./poc` — contains folders of the communication primitives

## Installation

First, install Python. Then:

```bash
git clone https://github.com/yonatan7175/arazim_local_production.git
cd arazim_local_production

sudo python3 install/install.py     # Linux
python install\install.py           # Windows (prompts for UAC elevation)
```

### What happens?

**Linux:** the app is copied to `/opt/Arazim_Local`, and `arazim_local` is
symlinked into `/usr/local/bin`. To launch the CLI tool, open a terminal and
run `arazim_local`.

**Windows:** the app is copied to `%ProgramData%\ArazimLocal`, and
`arazim_local.bat` is added to PATH (running `arazim_local.bat` in cmd launches
it). A shortcut to `arazim_local.bat` is also placed on the Desktop.

## Visiting the website

Open Chrome and go to `arazim.local`.
