# SDFServer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**SDFServer (Simple Download File Server)** – a lightweight Python-based HTTP server to download files and folders via a simple web interface over a local network.  

It provides:
- Directory browsing in your browser
- Direct file downloads
- On-the-fly ZIP64 streaming of entire folders (no temporary files)

---

## Features

- 📂 Clean web interface with a file/folder table view
- ⬇️ Download individual files
- 🗜️ Download folders as ZIP archives (streamed, ZIP64-enabled)
- 🔒 Startup safety screen with a warning and one-time PIN code
- ⚙️ Configurable via command-line options

---

## Installation

Requires **Python 3.8+**.

Clone the repository and run the server:

```bash
git clone https://github.com/yourname/sdfserver.git
cd sdfserver
python3 server.py --base-dir /path/to/share
```

---

## Usage

Start the server:

```bash
python3 server.py --base-dir ./share --port 8000
```

On startup, the server prints an **8-digit PIN** to the console.
You need to enter this PIN in your browser on the safety screen before accessing files.

Example: this server is running on a computer with IP `192.168.1.110` in the local network:

```
[i] Serving: /home/user/share
[i] URL:     http://0.0.0.0:8000/
[i] DIR_SIZE calculation: ON
[i] COMPRESS_LEVEL: 6
[i] WARNING GATE: ON
[i] PIN: 67190394
```

Now open `http://192.168.1.110:8000` in a browser on another computer and enter the PIN.

---

## Command-line options

| Flag                | Description                                                   | Default   |
|---------------------|---------------------------------------------------------------|-----------|
| `--base-dir PATH`   | Root directory to serve                                       | `.` (cwd) |
| `--dir-size`        | Show recursive folder sizes (may be slow on large trees)      | OFF       |
| `--host HOST`       | Host to bind (e.g. `0.0.0.0` or `127.0.0.1`)                  | `0.0.0.0` |
| `--port PORT`       | Port number                                                   | `8000`    |
| `--compress-level N`| ZIP deflate compression level (0..9, where 0 = none, 9 = max) | `6`       |
| `--no-warning`      | Disable the startup warning/PIN screen                        | false     |

---

## ⚠️ Security Warning

Do **NOT** expose **SDFServer** to public networks.

- ❌ No authentication — anyone can browse and download
- ✅ Use only in trusted environments (LAN, VPN, lab)

---

## License

MIT License – see [LICENSE](LICENSE) for details.

