#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SDFServer — Simple Download File Server
- Directory browsing with direct file download
- On-the-fly ZIP64 streaming for folders
- Startup safety gate (warning + 8-digit PIN)
- Cross-platform and permission-tolerant (Linux/Windows)

Notes:
- We avoid Path.resolve() on each entry (Windows may raise PermissionError for system folders).
- We keep all paths constrained inside BASE_DIR using string-based checks (abspath + common prefix).
- ZIP writer is a minimal streaming ZIP64 implementation (no temp files).
"""
import os
import io
import sys
import html
import struct
import posixpath
import urllib.parse
import zlib
import binascii
import argparse
import threading
import hashlib
import secrets
from typing import List
from http.cookies import SimpleCookie
from pathlib import Path
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# === Runtime-configurable (set in main() via argparse) ===
BASE_DIR: Path = Path(".").resolve()
DIR_SIZE: bool = False
COMPRESS_LEVEL: int = 6
REQUIRE_CONSENT: bool = True  # show safety warning + PIN before allowing access
PIN_CODE: str = ""            # 8-digit PIN generated at startup (when gate is enabled)

# === Static settings ===
TITLE = "SDFServer"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

MAX32 = 0xFFFFFFFF
MAX16 = 0xFFFF

SECRET_SALT = secrets.token_hex(16)

# ---------- Helpers: sizes, dates ----------
def human_size(n: int) -> str:
    """Convert bytes to human-readable size using base-2 units."""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024.0
    return f"{n:.0f} EB"

def fmt_mtime(ts: float) -> str:
    """Format mtime into 'YYYY-MM-DD HH:MM', tolerate weird timestamps."""
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "—"

def dir_size_bytes(path: Path) -> int:
    """
    Recursively sum file sizes inside a directory.

    Note:
    - We pass onerror=lambda e: None to ignore permission errors.
    - We skip symlinks and tolerate stat() failures per file.
    """
    total = 0
    try:
        for root, dirs, files in os.walk(path, onerror=lambda e: None):
            root_p = Path(root)
            for f in files:
                fp = root_p / f
                try:
                    if not fp.is_symlink():
                        total += fp.stat().st_size
                except Exception:
                    pass
    except Exception:
        pass
    return total

# ---------- Helpers: URL building & Content-Disposition ----------
def url_join_encoded(parts: List[str]) -> str:
    """Join path parts into URL, encoding each component (slashes kept as separators)."""
    enc_parts = [urllib.parse.quote(p, safe="") for p in parts]
    return "/".join(enc_parts)

def url_from_relpath(rel: Path, trailing_slash: bool = False) -> str:
    """
    Build a safe URL path from a relative Path, encoding each component.

    - rel is expected to be relative to BASE_DIR (no leading slash).
    - trailing_slash=True is used for directories to make browser navigation happy.
    """
    parts = [p for p in rel.as_posix().split("/") if p]
    url = "/" + url_join_encoded(parts)
    if trailing_slash:
        url += "/"
    return url or "/"

def encode_query_value(value: str) -> str:
    """Encode a query parameter value (encode slashes too)."""
    return urllib.parse.quote(value, safe="")

def content_disposition_attachment(filename: str) -> str:
    """
    Build Content-Disposition header for cross-locale filenames.
    RFC 6266: include ASCII fallback filename and UTF-8 filename*.
    """
    # ASCII fallback: replace non-ASCII with '_' and escape quotes/backslashes
    fallback = "".join((ch if 0x20 <= ord(ch) < 0x7F else "_") for ch in filename)
    fallback = fallback.replace("\\", "\\\\").replace('"', r"\"")
    # filename* with UTF-8 percent-encoding
    filename_star = "UTF-8''" + urllib.parse.quote(filename, safe="")
    return f'attachment; filename="{fallback}"; filename*={filename_star}'

# ---------- ZIP time ----------
def _dos_time_date_from_epoch(mtime: float):
    """
    Convert epoch seconds to MS-DOS time/date fields used by ZIP format.
    Year is clamped to [1980, 2107] as per specification constraints.
    """
    import time
    t = time.localtime(mtime if mtime > 0 else time.time())
    year = min(max(t.tm_year, 1980), 2107)
    dostime = ((t.tm_hour & 0x1F) << 11) | ((t.tm_min & 0x3F) << 5) | ((t.tm_sec // 2) & 0x1F)
    dosdate = (((year - 1980) & 0x7F) << 9) | ((t.tm_mon & 0x0F) << 5) | (t.tm_mday & 0x1F)
    return dostime, dosdate

# ---------- Streaming ZIP64 writer ----------
class ZipStreamWriter:
    """
    Minimal streaming ZIP writer supporting ZIP64 via data descriptors and extra fields.
    - add_file(): streams DEFLATE compressed data (method 8) in chunks.
    - add_dir_entry(): writes empty stored entry to represent a directory.
    - finish(): writes central directory and (ZIP64) end of central directory records.
    """
    LFH_SIG = 0x04034B50
    DD_SIG = 0x08074B50
    CDH_SIG = 0x02014B50
    EOCD_SIG = 0x06054B50
    Z64_EOCD_SIG = 0x06064B50
    Z64_LOC_SIG = 0x07064B50
    Z64_EXTRA_ID = 0x0001

    def __init__(self, write_cb):
        self.write = write_cb
        self._offset = 0
        self._central = []
        self._count = 0
        self._zip64_used = False  # true if any 32-bit field overflowed

    def _w(self, b: bytes):
        """Write bytes to client and advance offset. Swallow client disconnects."""
        try:
            self.write(b)
            self._offset += len(b)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # client closed connection — stop streaming quietly
            raise RuntimeError("client_disconnected")

    def _build_zip64_extra(self, uncomp=None, comp=None, lfh_offset=None):
        """Build ZIP64 extra field with optional (uncomp, comp, lfh_offset) 64-bit values."""
        payload = b""
        if uncomp is not None:
            payload += struct.pack("<Q", uncomp)
        if comp is not None:
            payload += struct.pack("<Q", comp)
        if lfh_offset is not None:
            payload += struct.pack("<Q", lfh_offset)
        return struct.pack("<HH", self.Z64_EXTRA_ID, len(payload)) + payload

    def add_file(self, abs_path: Path, arcname: str, compress_level: int = 6):
        """
        Add a file entry by streaming DEFLATE-compressed content and appending a data descriptor.
        We set LFH sizes to zero and provide real sizes via the data descriptor to keep streaming.
        """
        st = abs_path.stat()
        mt, md = _dos_time_date_from_epoch(st.st_mtime)
        flags = 0x0008 | 0x0800  # bit3: data descriptor present, bit11: UTF-8
        method = 8               # DEFLATE
        ver_needed_lfh = 20      # deflate, data descriptor
        ver_made = 0x0314        # arbitrary "made by" (Unix 3.20)
        name_bytes = arcname.encode("utf-8")
        extra_lfh = b""          # no ZIP64 fields in LFH; we add them to CDH if needed

        # Local File Header (sizes zero because streaming)
        lfh = struct.pack(
            "<IHHHHHIIIHH",
            self.LFH_SIG, ver_needed_lfh, flags, method, mt, md,
            0, 0, 0,
            len(name_bytes), len(extra_lfh)
        ) + name_bytes + extra_lfh

        lfh_offset = self._offset
        self._w(lfh)

        # Stream file content
        crc = 0
        comp_size = 0
        uncomp_size = 0
        comp = zlib.compressobj(compress_level, zlib.DEFLATED, wbits=-15)

        with abs_path.open("rb") as f:
            while True:
                chunk = f.read(128 * 1024)
                if not chunk:
                    break
                crc = binascii.crc32(chunk, crc) & 0xFFFFFFFF
                uncomp_size += len(chunk)
                c = comp.compress(chunk)
                if c:
                    comp_size += len(c)
                    self._w(c)

        tail = comp.flush()
        if tail:
            comp_size += len(tail)
            self._w(tail)

        # Data Descriptor (32-bit or ZIP64 variant)
        if comp_size > MAX32 or uncomp_size > MAX32:
            dd = struct.pack("<IIQQ", self.DD_SIG, crc, comp_size, uncomp_size)
            self._zip64_used = True
            ver_needed_cdh = 45  # ZIP64
        else:
            dd = struct.pack("<IIII", self.DD_SIG, crc, comp_size, uncomp_size)
            ver_needed_cdh = 20
        self._w(dd)

        # Values for central directory (truncate to 32-bit if ZIP64 extra is present)
        c_comp = comp_size if comp_size <= MAX32 else MAX32
        c_uncomp = uncomp_size if uncomp_size <= MAX32 else MAX32
        c_rel = lfh_offset if lfh_offset <= MAX32 else MAX32

        # ZIP64 extra (central directory only) if any 32-bit overflow happened
        extra_cdh = b""
        z64_parts = {}
        if uncomp_size > MAX32:
            z64_parts["uncomp"] = uncomp_size
        if comp_size > MAX32:
            z64_parts["comp"] = comp_size
        if lfh_offset > MAX32:
            z64_parts["lfh_offset"] = lfh_offset
        if z64_parts:
            extra_cdh += self._build_zip64_extra(
                uncomp=z64_parts.get("uncomp"),
                comp=z64_parts.get("comp"),
                lfh_offset=z64_parts.get("lfh_offset"),
            )
            self._zip64_used = True
            ver_needed_cdh = 45

        comment = b""
        # Central Directory Header
        cdh = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            self.CDH_SIG,
            ver_made,
            ver_needed_cdh,
            flags,
            method,
            mt, md,
            crc,
            c_comp,
            c_uncomp,
            len(name_bytes),
            len(extra_cdh),
            len(comment),
            0, 0, 0,
            c_rel
        ) + name_bytes + extra_cdh + comment

        self._central.append(cdh)
        self._count += 1

    def add_dir_entry(self, arcdir: str, mtime: float):
        """
        Add a directory entry (empty stored file with trailing slash).
        """
        if not arcdir.endswith("/"):
            arcdir += "/"
        name_bytes = arcdir.encode("utf-8")
        flags = 0x0800  # UTF-8
        method = 0     # stored (no data)
        ver_needed_lfh = 20
        ver_made = 0x0314
        mt, md = _dos_time_date_from_epoch(mtime)

        # LFH for a directory (no data)
        lfh = struct.pack(
            "<IHHHHHIIIHH",
            self.LFH_SIG, ver_needed_lfh, flags, method, mt, md,
            0, 0, 0, len(name_bytes), 0
        ) + name_bytes
        lfh_offset = self._offset
        self._w(lfh)

        # Central directory info (may require ZIP64 offset)
        c_rel = lfh_offset if lfh_offset <= MAX32 else MAX32
        extra_cdh = b""
        ver_needed_cdh = 20
        if lfh_offset > MAX32:
            extra_cdh += self._build_zip64_extra(lfh_offset=lfh_offset)
            self._zip64_used = True
            ver_needed_cdh = 45

        cdh = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            self.CDH_SIG, ver_made, ver_needed_cdh, flags, method, mt, md,
            0, 0, 0,
            len(name_bytes), len(extra_cdh), 0,
            0, 0, 0x10,  # external attrs: directory bit
            c_rel
        ) + name_bytes + extra_cdh
        self._central.append(cdh)
        self._count += 1

    def finish(self):
        """
        Write the central directory and end-of-central-directory records.
        Use ZIP64 EOCD + locator if any ZIP64 fields were used or counts/sizes overflow 32-bit.
        """
        cd_start = self._offset
        for c in self._central:
            self._w(c)
        cd_size = self._offset - cd_start

        need_zip64 = (self._zip64_used or cd_start > MAX32 or cd_size > MAX32 or self._count > MAX16)

        if need_zip64:
            # ZIP64 End of Central Directory
            z64_eocd_start = self._offset
            size_of_record = 44  # fixed size of ZIP64 EOCD record (after signature & size field)
            self._w(struct.pack(
                "<IQHHIIQQQQ",
                self.Z64_EOCD_SIG,
                size_of_record,
                0x0314,  # version made by (same as above)
                45,      # version needed to extract (ZIP64)
                0, 0,    # disk numbers
                self._count,
                self._count,
                cd_size,
                cd_start
            ))
            # ZIP64 EOCD locator
            self._w(struct.pack(
                "<IIQI",
                self.Z64_LOC_SIG,
                0,               # number of the disk with the start of the ZIP64 EOCD
                z64_eocd_start,  # relative offset
                1                # total number of disks
            ))
            # Classic EOCD with truncated values (as per spec)
            self._w(struct.pack(
                "<IHHHHIIH",
                self.EOCD_SIG,
                0, 0,
                min(self._count, MAX16),
                min(self._count, MAX16),
                min(cd_size, MAX32),
                min(cd_start, MAX32),
                0
            ))
        else:
            # Classic EOCD only
            self._w(struct.pack(
                "<IHHHHIIH",
                self.EOCD_SIG,
                0, 0,
                self._count,
                self._count,
                cd_size,
                cd_start,
                0
            ))

# ---------- HTTP Handler ----------
class FileServer(SimpleHTTPRequestHandler):
    # ===== Consent (safety gate) helpers =====
    def _has_consent(self) -> bool:
        """Return True if safety gate is disabled or consent cookie is set."""
        if not REQUIRE_CONSENT:
            return True
        raw = self.headers.get("Cookie")
        if not raw:
            return False
        c = SimpleCookie(raw)
        v = c.get("consent")
        if not v:
            return False
        expected = hashlib.sha256((PIN_CODE + SECRET_SALT).encode()).hexdigest()
        return secrets.compare_digest(v.value, expected)

    def _warning_page(self, redirect_path: str, error_msg: str = "") -> bytes:
        """
        Render the warning + PIN page (Agree is enabled only when checkbox + 8-digit PIN are set).
        The 'Exit' button navigates to about:blank (server keeps running).
        """
        # Normalize the redirect target to a path within this origin.
        try:
            rp = urllib.parse.urlsplit(redirect_path).path or "/"
        except Exception:
            rp = "/"
        err_html = f'<p style="color:#b91c1c"><strong>{html.escape(error_msg)}</strong></p>' if error_msg else ""
        html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(TITLE)} — Safety Warning</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;line-height:1.5;
     margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#f6f7fb}}
.card{{background:#fff;max-width:720px;margin:24px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.08)}}
.card header{{padding:20px 24px;border-bottom:1px solid #eee}}
.card header h1{{margin:0;font-size:20px}}
.card .content{{padding:20px 24px;color:#374151}}
.card .actions{{padding:20px 24px;border-top:1px solid #eee;display:flex;gap:12px;flex-wrap:wrap}}
label{{display:flex;gap:10px;align-items:flex-start;margin:8px 0}}
.btn{{border:1px solid #d1d5db;border-radius:10px;padding:10px 14px;background:#fff;cursor:pointer}}
.btn.primary{{background:#2563eb;color:#fff;border-color:#2563eb}}
.btn:disabled{{opacity:.45;cursor:not-allowed}}
small{{color:#6b7280}}
ul{{margin:.5em 0 .5em 1.2em}}
input[type="text"]{{font:inherit;padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;width:220px}}
.row{{display:flex;gap:12px;align-items:center;flex-wrap:wrap}}
</style>
<script>
function onStateChange() {{
  const ack = document.getElementById('ack');
  const pin = document.getElementById('pin');
  const agree = document.getElementById('agree');
  const pinOk = /^\\d{{8}}$/.test(pin.value.trim());
  agree.disabled = !(ack.checked && pinOk);
}}
function submitAgree() {{ document.getElementById('agreeForm').submit(); }}
</script>
</head>
<body>
  <div class="card" role="dialog" aria-labelledby="ttl">
    <header><h1 id="ttl">Safety warning</h1></header>
    <div class="content">
      {err_html}
      <p><strong>Do NOT expose this server to public networks.</strong></p>
      <ul>
        <li>No authentication, anyone can browse and download.</li>
        <li>Paths are local; accidental exposure may leak private data.</li>
        <li>Use only in trusted networks (home/LAN/VPN).</li>
      </ul>
      <div class="row">
        <label style="margin:0;">
          <input type="checkbox" id="ack" onchange="onStateChange()">
          <span>I understand the risks and want to proceed.</span>
        </label>
      </div>
      <div class="row">
        <label for="pin" style="min-width:120px;">Enter PIN:</label>
        <input type="text" id="pin" name="pin" inputmode="numeric" pattern="\\d{{8}}" maxlength="8"
               placeholder="8 digits" oninput="onStateChange()">
      </div>
      <small>PIN is printed in the server console. You can disable this screen with <code>--no-warning</code>.</small>
    </div>

    <div class="actions">
      <form id="agreeForm" method="POST" action="/consent">
        <input type="hidden" name="redirect" value="{html.escape(rp)}">
        <input type="hidden" id="pinField" name="pin" value="" />
        <button type="button" id="agree" class="btn primary" disabled onclick="
          document.getElementById('pinField').value = document.getElementById('pin').value.trim();
          submitAgree();
        ">Agree</button>
      </form>
      <button type="button" class="btn" onclick="window.location.href='about:blank'">Exit</button>
    </div>
  </div>
</body>
</html>"""
        return html_doc.encode("utf-8")

    def _serve_warning(self, error_msg: str = ""):
        """Send the warning page (HTTP 200 or 400 if error message present)."""
        body = self._warning_page(self.path, error_msg=error_msg)
        self.send_response(200 if not error_msg else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return None

    # ===== Standard helpers =====
    def translate_path(self, path):
        """
        Map URL path to a filesystem path, constrained inside BASE_DIR.
        We avoid Path.resolve() (Windows may raise PermissionError for system dirs).
        """
        # Extract and normalize the URL path
        path = urllib.parse.urlsplit(path).path
        norm = posixpath.normpath(urllib.parse.unquote(path))
        parts = [p for p in norm.split("/") if p and p not in (".", "..")]

        # Build absolute target under BASE_DIR (string-based to avoid touching the FS)
        base = os.path.abspath(str(BASE_DIR))
        target = os.path.abspath(os.path.join(base, *parts))

        # Constrain to BASE_DIR
        base_nc = os.path.normcase(base)
        target_nc = os.path.normcase(target)
        if os.path.commonprefix([target_nc, base_nc]) != base_nc:
            return base
        return target

    def do_GET(self):
        """Enforce consent gate for any GET until user accepts."""
        if REQUIRE_CONSENT and not self._has_consent():
            return self._serve_warning()
        return super().do_GET()

    def do_HEAD(self):
        """HEAD will also show the warning gate (small HTML) if not consented."""
        if REQUIRE_CONSENT and not self._has_consent():
            return self._serve_warning()
        return super().do_HEAD()

    def do_POST(self):
        """
        Handle consent POST:
        - /consent: validate PIN, set cookie, redirect to prior path
        Any other POST without consent -> show gate; with consent -> 404.
        """
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        fields = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)

        if parsed.path == "/consent":
            redirect_to = fields.get("redirect", ["/"])[0] or "/"
            pin = (fields.get("pin", [""])[0] or "").strip()
            # Server-side validation of PIN (UI also checks length)
            if REQUIRE_CONSENT and PIN_CODE and pin != PIN_CODE:
                return self._serve_warning("Invalid PIN. Please check the console and try again.")
            self.send_response(303)
            self.send_header("Location", redirect_to)
            # Cookie valid for session; SameSite=Lax to avoid cross-site corner cases
            cookie_val = hashlib.sha256((pin + SECRET_SALT).encode()).hexdigest()
            self.send_header("Set-Cookie", f"consent={cookie_val}; Path=/; SameSite=Lax")
            self.end_headers()
            return

        if REQUIRE_CONSENT and not self._has_consent():
            return self._serve_warning()
        self.send_error(404, "Not Found")
    def send_head(self):
        """
        Intercept /zip route for streaming ZIP.
        Delegate rest to file/dir handling (download files or list directories).
        """
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/zip":
            return self._handle_zip_stream(query)

        path = self.translate_path(self.path)
        if os.path.isdir(path):
            # Ensure trailing slash for directory URLs
            if not parsed.path.endswith("/"):
                new_path = parsed.path + "/"
                new_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, new_path, parsed.query, parsed.fragment))
                self.send_response(301)
                self.send_header("Location", new_url)
                self.end_headers()
                return None
            return self.list_directory(path)

        try:
            f = open(path, "rb")
        except OSError:
            self.send_error(404, "File not found")
            return None
        fs = os.fstat(f.fileno())
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(fs.st_size))
        self.send_header("Content-Disposition", content_disposition_attachment(os.path.basename(path)))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def list_directory(self, path):
        """
        Render a simple HTML directory listing with:
        - Name (files/dirs), Size, Modified, Actions (Download / Download as ZIP for dirs)
        - SVG icons embedded in-page (no external assets)
        """
        try:
            entries = os.listdir(path)
        except OSError:
            self.send_error(403, "Permission denied")
            return None

        # Sort: directories first, then files, each alphabetically (case-insensitive)
        entries.sort(key=lambda n: (not os.path.isdir(os.path.join(path, n)), n.lower()))
        enc = sys.getfilesystemencoding()
        displaypath = html.escape(urllib.parse.unquote(self.path))

        out = io.StringIO()
        out.write("<!doctype html><html><head>")
        out.write('<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
        out.write(f"<title>{TITLE} — {displaypath}</title>")
        out.write("""
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;margin:20px;line-height:1.45}
h1{margin:.2em 0 .6em}
table{border-collapse:collapse;width:100%;max-width:1200px}
th,td{border-bottom:1px solid #eee;padding:8px 6px;text-align:left;vertical-align:middle;white-space:nowrap}
th{background:#fafafa}
.name{white-space:normal}
.name a{text-decoration:none;color:#222}
.name a:hover{text-decoration:underline}
.btn{display:inline-block;border:1px solid #ddd;border-radius:6px;padding:6px 10px;text-decoration:none;color:#222;background:#f7f7f7}
.btn:hover{background:#eee}
.tag{font-size:.9em;color:#666;margin-left:.4em}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
</style>
<svg style="display:none;">
  <symbol id="icon-down" viewBox="0 0 48 48" fill="currentColor">
    <defs>
      <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#60A5FA"/>
        <stop offset="100%" stop-color="#2563EB"/>
      </linearGradient>
    </defs>
    <rect x="2" y="2" width="44" height="44" rx="10" fill="url(#g)"/>
    <rect x="21" y="10" width="6" height="18" rx="3" fill="#fff"/>
    <polygon points="12,26 36,26 24,38" fill="#fff"/>
  </symbol>
</svg>
<svg style="display:none;">
  <symbol id="icon-folder" viewBox="0 0 48 48" fill="currentColor">
    <path d="m 6,2.6440678 h 14 l 4,6.1210653 h 18 a 2,3.0605327 0 0 1 2,3.0605319 V 39.37046 a 4,6.1210653 0 0 1 -4,6.121065 H 6 A 4,6.1210653 0 0 1 2,39.37046 V 8.7651331 A 4,6.1210653 0 0 1 6,2.6440678 Z" fill="#fbbf24"/>
    <path d="M 2,11.825665 H 46 V 39.37046 a 4,6.1210653 0 0 1 -4,6.121065 H 6 A 4,6.1210653 0 0 1 2,39.37046 Z" fill="#f59e0b"/>
  </symbol>
</svg>
<svg style="display:none;">
  <symbol id="icon-file" viewBox="0 0 48 48" fill="currentColor">
    <path d="M7.356 1.272h27.878l9.293 9.077v31.769a4.646 4.538 0 0 1-4.646 4.538H7.356A4.646 4.538 0 0 1 2.71 42.118V5.81A4.646 4.538 0 0 1 7.356 1.272Z"
          fill="#ffffff" stroke="#cbd5e1" stroke-width="2.296" stroke-linejoin="round"/>
    <path d="M35.234 1.272v9.077h9.293Z"
          fill="#e2e8f0" stroke="#cbd5e1" stroke-width="2.296" stroke-linejoin="round"/>
    <path d="M12.002 17.156h25.554" fill="none" stroke="#94a3b8" stroke-width="2.296" stroke-linecap="round"/>
    <path d="M12.002 21.695h20.908" fill="none" stroke="#94a3b8" stroke-width="2.296" stroke-linecap="round"/>
    <path d="M12.002 26.233h25.554" fill="none" stroke="#94a3b8" stroke-width="2.296" stroke-linecap="round"/>
    <path d="M12.002 30.772h18.585" fill="none" stroke="#94a3b8" stroke-width="2.296" stroke-linecap="round"/>
    <path d="M12.002 35.31h23.231" fill="none" stroke="#94a3b8" stroke-width="2.296" stroke-linecap="round"/>
    <path d="M12.002 39.849h13.939" fill="none" stroke="#94a3b8" stroke-width="2.296" stroke-linecap="round"/>
  </symbol>
</svg>
<svg style="display:none;">
  <symbol id="icon-back" viewBox="0 0 48 48" fill="currentColor">
    <rect width="48" height="48" rx="8" fill="#4f46e5"/>
    <path d="M20 34L10 24l10-10" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M38 24H12" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round"/>
  </symbol>
</svg>
""")
        out.write("</head><body>")
        out.write(f"<h1>{TITLE}</h1>")

        # Parent link (safe, without resolve)
        base_abs = os.path.abspath(str(BASE_DIR))
        here_abs = os.path.abspath(path)
        if os.path.normcase(here_abs) != os.path.normcase(base_abs):
            parent_abs = os.path.abspath(os.path.join(here_abs, os.pardir))
            try:
                rel_parent = os.path.relpath(parent_abs, base_abs)
            except Exception:
                rel_parent = ""
            parent_url = url_from_relpath(Path(rel_parent), trailing_slash=True)
            out.write(f'<p><a class="btn" href="{parent_url}"><svg width="16" height="16"><use href="#icon-back"></use></svg> Back</a></p>')

        out.write("<table><thead><tr>")
        out.write("<th>Name</th><th>Size</th><th>Modified</th><th>Actions</th>")
        out.write("</tr></thead><tbody>")

        # Emit rows (tolerating permission errors)
        for name in entries:
            full = os.path.join(path, name)

            # Relative path w.r.t BASE_DIR (no resolve, string-based)
            try:
                rel = Path(os.path.relpath(full, os.path.abspath(str(BASE_DIR))))
            except Exception:
                continue  # skip weird/unresolvable entries

            # Dir or file? (this may still fail on some special entries)
            try:
                is_dir = os.path.isdir(full)
            except Exception:
                continue

            # Best-effort stat
            st = None
            mtime = 0
            try:
                st = os.stat(full)
                mtime = st.st_mtime
            except Exception:
                pass

            display_name = html.escape(name)

            if is_dir:
                browse_url = url_from_relpath(rel, trailing_slash=True)
                zip_q = encode_query_value(rel.as_posix())
                zip_url = f"/zip?path={zip_q}"
                size_str = human_size(dir_size_bytes(Path(full))) if DIR_SIZE else "—"
                out.write("<tr>")
                out.write(f'<td class="name"><svg width="16" height="16"><use href="#icon-folder"></use></svg> '
                          f'<a href="{browse_url}">{display_name}</a> <span class="tag">dir</span></td>')
                out.write(f'<td class="mono">{size_str}</td>')
                out.write(f'<td class="mono">{fmt_mtime(mtime)}</td>')
                out.write(f'<td><a class="btn" href="{zip_url}"><svg width="16" height="16"><use href="#icon-down"></use></svg> '
                          f'Download as ZIP</a></td>')
                out.write("</tr>")
            else:
                file_url = url_from_relpath(rel)
                size_str = human_size(st.st_size) if st else "—"
                out.write("<tr>")
                out.write(f'<td class="name"><svg width="16" height="16"><use href="#icon-file"></use></svg> '
                          f'<a href="{file_url}">{display_name}</a></td>')
                out.write(f'<td class="mono">{size_str}</td>')
                out.write(f'<td class="mono">{fmt_mtime(mtime)}</td>')
                out.write(f'<td><a class="btn" href="{file_url}"><svg width="16" height="16"><use href="#icon-down"></use></svg> '
                          f'Download</a></td>')
                out.write("</tr>")

        out.write("</tbody></table></body></html>")
        data = out.getvalue().encode(enc, "surrogateescape")
        out.close()

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        return io.BytesIO(data)

    def _handle_zip_stream(self, query):
        """
        Route: GET /zip?path=<relpath>
        Stream a ZIP64 archive of a folder recursively, writing entries on-the-fly.
        We:
        - Validate <relpath> stays within BASE_DIR (string-based).
        - Tolerate permission errors (skip unreadable entries).
        - Write ZIP64 where needed (sizes/offsets > 4GB or count > 65535).
        """
        relpath = query.get("path", [""])[0]
        base_abs = os.path.abspath(str(BASE_DIR))
        target_abs = os.path.abspath(os.path.join(
            base_abs, *[p for p in relpath.split("/") if p and p not in (".", "..")]
        ))

        base_nc = os.path.normcase(base_abs)
        target_nc = os.path.normcase(target_abs)
        if os.path.commonprefix([target_nc, base_nc]) != base_nc:
            self.send_error(404, "Invalid path")
            return None

        if not os.path.isdir(target_abs):
            self.send_error(404, "Directory not found")
            return None

        zip_name = (os.path.basename(target_abs) or "root") + ".zip"

        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", content_disposition_attachment(zip_name))
        self.end_headers()

        try:
            zw = ZipStreamWriter(self.wfile.write)
            base_name = os.path.basename(target_abs) or "root"

            for root, dirs, files in os.walk(target_abs, onerror=lambda e: None):
                rel = os.path.relpath(root, target_abs)
                root_p = Path(root)

                # Emit a directory entry (not for the root itself)
                if rel != ".":
                    dir_arc = str(Path(base_name) / Path(rel)).replace("\\", "/")
                    try:
                        dir_mtime = root_p.stat().st_mtime
                    except Exception:
                        import time
                        dir_mtime = time.time()
                    try:
                        zw.add_dir_entry(dir_arc, dir_mtime)
                    except RuntimeError as e:
                        if str(e) == "client_disconnected":
                            return None
                        raise
                    except Exception:
                        # Skip dir entry on error (permission, etc.)
                        pass

                # Emit files
                for f in files:
                    fp = root_p / f
                    arc = str(Path(base_name) / Path(rel) / f).replace("\\", "/")
                    try:
                        zw.add_file(fp, arc, compress_level=COMPRESS_LEVEL)
                    except FileNotFoundError:
                        continue
                    except PermissionError:
                        continue
                    except RuntimeError as e:
                        if str(e) == "client_disconnected":
                            # Client aborted download: finish quietly
                            return None
                        raise
                    except Exception:
                        # Skip unexpected errors per file (keeps stream alive)
                        continue

            # Empty directory case: add a single dir entry
            try:
                is_empty = True
                with os.scandir(target_abs) as it:
                    for _ in it:
                        is_empty = False
                        break
            except Exception:
                is_empty = False  # if scandir fails, do nothing special

            if is_empty:
                try:
                    base_mtime = Path(target_abs).stat().st_mtime
                except Exception:
                    import time
                    base_mtime = time.time()
                try:
                    zw.add_dir_entry(base_name + "/", base_mtime)
                except Exception:
                    pass

            zw.finish()
        except RuntimeError as e:
            if str(e) == "client_disconnected":
                # Client disconnected mid-stream: just stop quietly.
                return None
            raise

        return None

    def end_headers(self):
        """Disable caching to keep directory views and downloads always fresh."""
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

# ---------- CLI ----------
def parse_args():
    """Define and parse command-line options."""
    p = argparse.ArgumentParser(
        description="SDFServer — simple file server: download files directly or whole folders as ZIP."
    )
    p.add_argument("--base-dir", default=".", help="Root directory to serve (default: current directory).")
    p.add_argument("--dir-size", action="store_true", help="Enable recursive directory size calculation (default: OFF).")
    p.add_argument("--host", default=HOST, help=f"Host to bind (default from env HOST or {HOST}).")
    p.add_argument("--port", type=int, default=PORT, help=f"Port to bind (default from env PORT or {PORT}).")
    p.add_argument("--compress-level", type=int, default=6, help="ZIP deflate level 0..9 (default: 6).")
    p.add_argument("--no-warning", action="store_true", help="Disable the warning/PIN screen.")
    return p.parse_args()

def run():
    """Start the threaded HTTP server."""
    print(f"[i] Serving: {BASE_DIR}")
    print(f"[i] URL:     http://{HOST}:{PORT}/")
    print(f"[i] DIR_SIZE calculation: {'ON' if DIR_SIZE else 'OFF'}")
    print(f"[i] COMPRESS_LEVEL: {COMPRESS_LEVEL}")
    print(f"[i] WARNING GATE: {'ON' if REQUIRE_CONSENT else 'OFF'}")
    if REQUIRE_CONSENT and PIN_CODE:
        print(f"[i] PIN: {PIN_CODE}")
    with ThreadingHTTPServer((HOST, PORT), FileServer) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Stopped.")

if __name__ == "__main__":
    # Parse CLI and apply runtime config
    args = parse_args()
    BASE_DIR = Path(args.base_dir).expanduser().resolve()
    if not BASE_DIR.exists() or not BASE_DIR.is_dir():
        print(f"Error: --base-dir '{BASE_DIR}' is not an existing directory.", file=sys.stderr)
        sys.exit(2)
    DIR_SIZE = bool(args.dir_size)
    HOST = args.host
    PORT = int(args.port)
    COMPRESS_LEVEL = max(0, min(9, int(args.compress_level)))
    REQUIRE_CONSENT = not bool(args.no_warning)
    # Generate 8-digit PIN for the safety gate
    if REQUIRE_CONSENT:
        PIN_CODE = "".join(secrets.choice("0123456789") for _ in range(8))
    else:
        PIN_CODE = ""
    run()
