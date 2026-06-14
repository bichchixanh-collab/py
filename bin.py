#!/usr/bin/env python3
"""
Binary String Translator (JAR edition)
Scan, translate, and patch Chinese/Vietnamese strings in structured binary files
inside a .jar archive. Skips .class files — targets binary data files only.

Auto-detected string encodings (per file):
  java-mutf8  : [2-byte BE length] + UTF-8   (Java serialised data, .bin, .dat …)
  len1-utf8   : [1-byte length]    + UTF-8   (.XSE scripts, RPGMaker, Unity assets …)
  len2le-utf8 : [2-byte LE length] + UTF-8   (various game engines)
  utf-8       : raw CJK UTF-8 byte sequences
  utf-16-le   : UTF-16 Little Endian
  utf-16-be   : UTF-16 Big Endian

Patch method: in-place byte replacement inside the JAR archive.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import zipfile
import struct
import os
import re
import time
from io import BytesIO

try:
    from deep_translator import GoogleTranslator
    TRANSLATOR_OK = True
except ImportError:
    TRANSLATOR_OK = False

try:
    from unidecode import unidecode
    UNIDECODE_OK = True
except ImportError:
    UNIDECODE_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# Regex helpers
# ─────────────────────────────────────────────────────────────────────────────
CJK_UTF8_BYTES = re.compile(b'(?:[\xe4-\xe9][\x80-\xbf]{2})+')
CJK_TEXT_RE    = re.compile(r'[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]+')

RE_CHINESE = re.compile(
    r'[\u4e00-\u9fff'
    r'\u3400-\u4dbf'
    r'\uf900-\ufaff]'
)
RE_VIETNAMESE = re.compile(
    r'[ăắằẳẵặĂẮẰẲẴẶ'
    r'ơớờởỡợƠỚỜỞỠỢ'
    r'ưứừửữựƯỨỪỬỮỰ'
    r'đĐ'
    r'ấầẩẫậẤẦẨẪẬ'
    r'ếềểễệẾỀỂỄỆ'
    r'ốồổỗộỐỒỔỖỘ'
    r'ỉịỈỊ'
    r'ọỏỌỎ'
    r'ụủỤỦ'
    r'ỳỵỷỹỲỴỶỸ]'
)

def has_chinese(s: str) -> bool:
    return bool(RE_CHINESE.search(s))

def has_vietnamese(s: str) -> bool:
    return bool(RE_VIETNAMESE.search(s))

def has_target_language(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    return has_chinese(s) or has_vietnamese(s)

# ─────────────────────────────────────────────────────────────────────────────
# JAR entry filter
# ─────────────────────────────────────────────────────────────────────────────
# Extensions that are definitely binary data files worth scanning
BINARY_DATA_EXTS = {
    '.bin', '.dat', '.res', '.pak', '.db', '.ldb',
    '.xse', '.ese', '.rse',                         # script archives
    '.arc', '.arc2', '.arc3',
    '.lpk', '.npk', '.mpq',
    '.sav', '.save',
    '.bytes',                                        # Unity TextAsset binary
    '.assets',
    '',                                              # no extension
}
# Extensions to always skip
SKIP_EXTS = {
    '.class',                                        # Java bytecode — handled by noapi.py
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp',
    '.mp3', '.ogg', '.wav', '.flac', '.m4a',
    '.mp4', '.avi', '.mov',
    '.ttf', '.otf', '.woff', '.woff2',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.exe', '.dll', '.so', '.dylib',
    '.xml', '.json', '.txt', '.csv', '.ini', '.cfg',
    '.html', '.htm', '.yaml', '.yml',
    '.properties', '.manifest', '.mf',
    '.sf', '.rsa', '.dsa', '.ec',                   # JAR signature files
}
SKIP_PREFIXES = ('META-INF/',)


def _should_scan_entry(name: str, scan_noext: bool) -> bool:
    """Return True if this JAR entry should be scanned for binary strings."""
    for p in SKIP_PREFIXES:
        if name.startswith(p):
            return False
    basename = os.path.basename(name)
    if not basename:          # directory entry
        return False
    ext = os.path.splitext(basename)[1].lower()
    if ext in SKIP_EXTS:
        return False
    if ext in BINARY_DATA_EXTS:
        return True
    if scan_noext and ext == '':
        return True
    return False


def _is_binary_data(data: bytes) -> bool:
    """
    Quick check: does this byte sequence look like structured binary data
    (as opposed to plain UTF-8 text)?
    Returns True if we should attempt a binary scan.
    """
    if len(data) < 4:
        return False
    # Null bytes → binary
    if b'\x00' in data[:4096]:
        return True
    # High byte ratio > 15% → binary
    sample     = data[:4096]
    high_bytes = sum(1 for b in sample if b > 0x7f)
    if high_bytes / len(sample) > 0.15:
        return True
    # CJK UTF-8 sequences present → worth scanning
    if CJK_UTF8_BYTES.search(sample):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Encoding detection
# ─────────────────────────────────────────────────────────────────────────────
MAX_FIELD_LEN = 512

def _has_control(b: bytes) -> bool:
    """True if chunk contains control bytes other than tab / LF / CR."""
    return any(c < 0x20 and c not in (0x09, 0x0a, 0x0d) for c in b)


def _count_len_prefixed(data: bytes, prefix_size: int, byteorder: str) -> int:
    """Count valid length-prefixed UTF-8 CJK fields."""
    count = 0
    dlen  = len(data)
    for pos in range(dlen - prefix_size - 1):
        fl = int.from_bytes(data[pos:pos + prefix_size], byteorder)
        if fl < 1 or fl > MAX_FIELD_LEN:
            continue
        end = pos + prefix_size + fl
        if end > dlen:
            continue
        chunk = data[pos + prefix_size:end]
        if not CJK_UTF8_BYTES.search(chunk):
            continue
        if _has_control(chunk):
            continue
        try:
            chunk.decode('utf-8', errors='strict')
            count += 1
        except UnicodeDecodeError:
            pass
    return count


def detect_encoding(data: bytes) -> str:
    """
    Auto-detect the best string encoding for a binary blob.
    Returns one of:
      'java-mutf8' | 'len1-utf8' | 'len2le-utf8' | 'utf-8' | 'utf-16-le' | 'utf-16-be'
    """
    if len(data) < 4:
        return 'utf-8'

    # BOM
    if data[:2] == b'\xff\xfe':
        return 'utf-16-le'
    if data[:2] == b'\xfe\xff':
        return 'utf-16-be'

    # Score each length-prefix scheme
    score_mutf8  = _count_len_prefixed(data, 2, 'big')
    score_len2le = _count_len_prefixed(data, 2, 'little')
    score_len1   = _count_len_prefixed(data, 1, 'big')

    THRESHOLD = 3
    best = max(score_mutf8, score_len2le, score_len1)
    if best >= THRESHOLD:
        if score_len1 > score_mutf8 and score_len1 > score_len2le:
            return 'len1-utf8'
        if score_len2le > score_mutf8:
            return 'len2le-utf8'
        return 'java-mutf8'

    # Raw CJK UTF-8 density
    cjk_matches = CJK_UTF8_BYTES.findall(data)
    if cjk_matches:
        cjk_total = sum(len(m) for m in cjk_matches)
        if cjk_total / len(data) > 0.02:
            return 'utf-8'

    # Null-ratio → UTF-16
    null_ratio = data.count(b'\x00') / len(data)
    if null_ratio > 0.25:
        sample   = min(len(data), 1024)
        le_score = sum(1 for i in range(1, sample, 2) if data[i] == 0)
        be_score = sum(1 for i in range(0, sample, 2) if data[i] == 0)
        return 'utf-16-le' if le_score >= be_score else 'utf-16-be'

    # Heuristic CJK position for UTF-16 without BOM
    if len(data) >= 6:
        sample = min(len(data), 512)
        cjk_le = sum(1 for i in range(1, sample - 1, 2) if 0x4e <= data[i] <= 0x9f)
        cjk_be = sum(1 for i in range(0, sample - 1, 2) if 0x4e <= data[i] <= 0x9f)
        if cjk_le >= 4 and cjk_le > cjk_be * 2:
            return 'utf-16-le'
        if cjk_be >= 4 and cjk_be > cjk_le * 2:
            return 'utf-16-be'

    return 'utf-8'


# ─────────────────────────────────────────────────────────────────────────────
# Scanners
# ─────────────────────────────────────────────────────────────────────────────

def _scan_len_prefixed(data: bytes, jar_entry: str,
                       prefix_size: int, byteorder: str,
                       enc_label: str) -> list:
    """Generic scanner: [N-byte length prefix][UTF-8 CJK content]."""
    entries = []
    seen    = set()
    dlen    = len(data)

    for pos in range(dlen - prefix_size):
        fl = int.from_bytes(data[pos:pos + prefix_size], byteorder)
        if fl < 1 or fl > MAX_FIELD_LEN:
            continue
        end = pos + prefix_size + fl
        if end > dlen:
            continue
        chunk = data[pos + prefix_size:end]

        if not CJK_UTF8_BYTES.search(chunk):
            continue
        if _has_control(chunk):
            continue
        try:
            text = chunk.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            continue

        if not any('\u4e00' <= c <= '\u9fff' for c in text):
            continue
        if pos in seen:
            continue
        seen.add(pos)

        entries.append({
            'jar_entry':   jar_entry,
            'offset':      pos,
            'encoding':    enc_label,
            'original':    text,
            'translated':  text,
            'enabled':     True,
            'byte_length': fl,
            'prefix_size': prefix_size,
            'byteorder':   byteorder,
        })

    return entries


def _scan_utf8_raw(data: bytes, jar_entry: str) -> list:
    """Scan raw UTF-8 CJK byte sequences."""
    entries = []
    for m in CJK_UTF8_BYTES.finditer(data):
        byte_off = m.start()
        try:
            full_text = m.group(0).decode('utf-8')
        except Exception:
            continue
        for m2 in CJK_TEXT_RE.finditer(full_text):
            cjk_text  = m2.group(0)
            if len(cjk_text) < 1 or '\ufffd' in cjk_text:
                continue
            cjk_bytes = cjk_text.encode('utf-8')
            sub_off   = data.find(cjk_bytes, byte_off)
            if sub_off < 0:
                continue
            entries.append({
                'jar_entry':   jar_entry,
                'offset':      sub_off,
                'encoding':    'utf-8',
                'original':    cjk_text,
                'translated':  cjk_text,
                'enabled':     True,
                'byte_length': len(cjk_bytes),
                'prefix_size': 0,
                'byteorder':   '',
            })
    return entries


def _scan_utf16(data: bytes, jar_entry: str, enc_name: str) -> list:
    entries = []
    try:
        text = data.decode(enc_name, errors='replace')
    except Exception:
        return []
    for m in CJK_TEXT_RE.finditer(text):
        raw = m.group(0)
        if len(raw) < 1 or '\ufffd' in raw:
            continue
        byte_off  = m.start() * 2
        raw_bytes = raw.encode(enc_name, errors='replace')
        if byte_off + len(raw_bytes) > len(data):
            continue
        if data[byte_off:byte_off + len(raw_bytes)] != raw_bytes:
            continue
        entries.append({
            'jar_entry':   jar_entry,
            'offset':      byte_off,
            'encoding':    enc_name,
            'original':    raw,
            'translated':  raw,
            'enabled':     True,
            'byte_length': len(raw_bytes),
            'prefix_size': 0,
            'byteorder':   '',
        })
    return entries


def extract_strings_from_binary(data: bytes, jar_entry: str) -> list:
    """
    Detect encoding and extract CJK strings from a binary blob.
    Returns list of entry dicts.
    """
    enc = detect_encoding(data)

    if enc == 'java-mutf8':
        raw = _scan_len_prefixed(data, jar_entry, 2, 'big', 'java-mutf8')
    elif enc == 'len1-utf8':
        raw = _scan_len_prefixed(data, jar_entry, 1, 'big', 'len1-utf8')
    elif enc == 'len2le-utf8':
        raw = _scan_len_prefixed(data, jar_entry, 2, 'little', 'len2le-utf8')
    elif enc == 'utf-8':
        raw = _scan_utf8_raw(data, jar_entry)
    else:
        raw = _scan_utf16(data, jar_entry, enc)

    # Deduplicate by (offset, original)
    seen    = set()
    results = []
    for e in raw:
        key = (e['offset'], e['original'])
        if key in seen:
            continue
        seen.add(key)
        results.append(e)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# JAR scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_jar(jar_path: str, scan_noext: bool, progress_cb=None) -> list:
    results = []
    try:
        zf = zipfile.ZipFile(jar_path, 'r')
    except Exception as e:
        print(f"Cannot open JAR: {e}")
        return results

    with zf:
        all_names = zf.namelist()
        entries   = [n for n in all_names if _should_scan_entry(n, scan_noext)]
        total     = len(entries)

        for i, name in enumerate(entries):
            if progress_cb:
                progress_cb(i + 1, total, name)
            try:
                data = zf.read(name)
            except Exception:
                continue

            if not _is_binary_data(data):
                continue

            strings = extract_strings_from_binary(data, name)
            results.extend(strings)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Patcher
# ─────────────────────────────────────────────────────────────────────────────

def _patch_blob(data: bytes, entries: list) -> bytes:
    """
    Patch a binary blob in-place (returns new bytes).
    Processes entries from highest offset to lowest to keep offsets stable.
    """
    buf = bytearray(data)

    sorted_entries = sorted(
        [e for e in entries if e['enabled'] and e['translated'] != e['original']],
        key=lambda e: e['offset'],
        reverse=True,
    )

    for e in sorted_entries:
        off      = e['offset']
        enc      = e['encoding']
        old_text = e['original']
        new_text = e['translated']
        ps       = e.get('prefix_size', 0)

        try:
            old_raw = old_text.encode('utf-8')
            new_raw = new_text.encode('utf-8')
        except Exception:
            continue

        if enc in ('java-mutf8', 'len2le-utf8', 'len1-utf8'):
            # Build old block and new block
            if enc == 'java-mutf8':
                old_lb = struct.pack('>H', len(old_raw))
                new_lb = struct.pack('>H', len(new_raw))
            elif enc == 'len2le-utf8':
                old_lb = struct.pack('<H', len(old_raw))
                new_lb = struct.pack('<H', len(new_raw))
            else:  # len1-utf8
                if len(new_raw) > 255:
                    new_raw = new_raw[:255]
                old_lb = struct.pack('B', len(old_raw))
                new_lb = struct.pack('B', len(new_raw))

            old_block = old_lb + old_raw
            new_block = new_lb + new_raw

            bs = off
            be = off + len(old_block)
            if be > len(buf):
                continue
            if buf[bs:be] != old_block:
                idx = bytes(buf).find(old_block, max(0, off - 4))
                if idx < 0:
                    continue
                bs, be = idx, idx + len(old_block)
            buf[bs:be] = new_block

        elif enc == 'utf-8':
            bs = off
            be = off + len(old_raw)
            if be > len(buf):
                continue
            if buf[bs:be] != old_raw:
                idx = bytes(buf).find(old_raw, max(0, off - 4))
                if idx < 0:
                    continue
                bs, be = idx, idx + len(old_raw)
            # Fit new_raw into exact same byte span (truncate / space-pad)
            if len(new_raw) > len(old_raw):
                new_raw = new_raw[:len(old_raw)]
            elif len(new_raw) < len(old_raw):
                new_raw = new_raw + b' ' * (len(old_raw) - len(new_raw))
            buf[bs:be] = new_raw

        elif enc in ('utf-16-le', 'utf-16-be'):
            codec = enc  # 'utf-16-le' or 'utf-16-be'
            try:
                old_r16 = old_text.encode(codec)
                new_r16 = new_text.encode(codec)
            except Exception:
                continue
            bs = off
            be = off + len(old_r16)
            if be > len(buf):
                continue
            if buf[bs:be] != old_r16:
                idx = bytes(buf).find(old_r16, max(0, off - 4))
                if idx < 0:
                    continue
                bs, be = idx, idx + len(old_r16)
            if len(new_r16) > len(old_r16):
                new_r16 = new_r16[:len(old_r16)]
            elif len(new_r16) < len(old_r16):
                new_r16 = new_r16 + b'\x00' * (len(old_r16) - len(new_r16))
            buf[bs:be] = new_r16

    return bytes(buf)


def patch_jar(jar_path: str, out_path: str, string_list: list, progress_cb=None):
    """
    Re-pack the JAR, patching each binary entry that has changed strings.
    Unmodified entries are copied verbatim.
    """
    # Group changes by JAR entry name
    entry_map: dict = {}
    for item in string_list:
        if not item['enabled']:
            continue
        if item['translated'] == item['original']:
            continue
        name = item['jar_entry']
        if name not in entry_map:
            entry_map[name] = []
        entry_map[name].append(item)

    with zipfile.ZipFile(jar_path, 'r') as zin:
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            names = zin.namelist()
            total = len(names)
            for i, name in enumerate(names):
                if progress_cb:
                    progress_cb(i + 1, total, name)
                data = zin.read(name)
                if name in entry_map:
                    try:
                        data = _patch_blob(data, entry_map[name])
                    except Exception as ex:
                        print(f"Patch error {name}: {ex}")
                zout.writestr(zipfile.ZipInfo(name), data)


# ─────────────────────────────────────────────────────────────────────────────
# Byte-size helper (used by the edit popup)
# ─────────────────────────────────────────────────────────────────────────────

def _calc_byte_sizes(item: dict, new_text: str):
    """
    Return (orig_bytes, new_bytes, limit_bytes, can_grow).
    For length-prefixed formats the limit is the prefix max.
    For raw UTF-8/UTF-16 the limit equals orig_bytes (fixed-size slot).
    can_grow is True for length-prefixed formats.
    """
    enc = item['encoding']
    old_raw = item['original'].encode('utf-8')
    try:
        new_raw = new_text.encode('utf-8')
    except Exception:
        new_raw = b''

    if enc in ('java-mutf8', 'len2le-utf8'):
        limit    = 65535
        can_grow = True
        return len(old_raw), len(new_raw), limit, can_grow
    elif enc == 'len1-utf8':
        limit    = 255
        can_grow = True
        return len(old_raw), len(new_raw), limit, can_grow
    elif enc in ('utf-16-le', 'utf-16-be'):
        codec    = enc
        old_r16  = item['original'].encode(codec)
        try:
            new_r16 = new_text.encode(codec)
        except Exception:
            new_r16 = b''
        return len(old_r16), len(new_r16), len(old_r16), False
    else:  # utf-8 raw — fixed-size slot
        return len(old_raw), len(new_raw), len(old_raw), False


# ─────────────────────────────────────────────────────────────────────────────
# Translation
# ─────────────────────────────────────────────────────────────────────────────
_translate_cache   = {}
_google_translator = None

def get_translator():
    global _google_translator
    if not TRANSLATOR_OK:
        return None
    if _google_translator is None:
        _google_translator = GoogleTranslator(source='zh-CN', target='vi')
    return _google_translator


def translate_batch(items: list, indices: list, accent: bool,
                    progress_cb=None, stop_flag=None):
    tr = get_translator()
    if tr is None:
        return
    total = len(indices)
    for n, idx in enumerate(indices):
        if stop_flag and stop_flag():
            break
        item     = items[idx]
        src_text = item['original']
        if not has_chinese(src_text):
            if progress_cb:
                progress_cb(n + 1, total)
            continue
        try:
            if src_text in _translate_cache:
                vi = _translate_cache[src_text]
            else:
                vi = tr.translate(src_text)
                _translate_cache[src_text] = vi
            if vi is None or not vi.strip():
                if progress_cb:
                    progress_cb(n + 1, total)
                continue
            if not accent and UNIDECODE_OK:
                vi = unidecode(vi)
            item['translated'] = vi
        except Exception:
            pass
        if progress_cb:
            progress_cb(n + 1, total)
        time.sleep(0.01)


# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────
PAGE_SIZE = 200

# Dark theme palette
BG       = '#1e1e2e'
BG2      = '#181825'
SURFACE  = '#313244'
SURFACE2 = '#45475a'
FG       = '#cdd6f4'
BLUE     = '#89b4fa'
LBLUE    = '#74c7ec'
GREEN    = '#a6e3a1'
YELLOW   = '#f9e2af'
RED      = '#f38ba8'
PEACH    = '#fab387'


class CopyButton(tk.Label):
    def __init__(self, parent, get_text_fn, **kwargs):
        super().__init__(parent, text='⧉', cursor='hand2',
                         font=('Segoe UI', 8), fg=BLUE, bg=BG,
                         padx=2, pady=0, **kwargs)
        self.get_text_fn = get_text_fn
        self.bind('<Button-1>', self._copy)
        self.bind('<Enter>',    lambda e: self.config(fg=LBLUE))
        self.bind('<Leave>',    lambda e: self.config(fg=BLUE))

    def _copy(self, _=None):
        text = self.get_text_fn()
        self.clipboard_clear()
        self.clipboard_append(text)
        self.config(text='✓', fg=GREEN)
        self.after(800, lambda: self.config(text='⧉', fg=BLUE))


# ── Byte-size meter shown in the edit popup ───────────────────────────────────

class ByteMeter(tk.Frame):
    """
    Compact widget that shows:
      Orig: XX B  →  New: YY B  [  progress-bar  ]  status-label
    Updates live as the user types.
    """
    BAR_W = 160

    def __init__(self, parent, item: dict, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        self.item = item

        tk.Label(self, text='Bytes gốc:', bg=BG, fg=FG,
                 font=('Consolas', 8)).pack(side='left')
        self.lbl_orig = tk.Label(self, text='', bg=BG, fg=YELLOW,
                                 font=('Consolas', 8, 'bold'), width=6)
        self.lbl_orig.pack(side='left')

        tk.Label(self, text='→  Mới:', bg=BG, fg=FG,
                 font=('Consolas', 8)).pack(side='left', padx=(6, 0))
        self.lbl_new = tk.Label(self, text='', bg=BG, fg=GREEN,
                                font=('Consolas', 8, 'bold'), width=6)
        self.lbl_new.pack(side='left')

        tk.Label(self, text='/ Giới hạn:', bg=BG, fg=FG,
                 font=('Consolas', 8)).pack(side='left')
        self.lbl_limit = tk.Label(self, text='', bg=BG, fg=FG,
                                  font=('Consolas', 8), width=6)
        self.lbl_limit.pack(side='left')

        # Canvas bar
        self.canvas = tk.Canvas(self, width=self.BAR_W, height=12,
                                bg=SURFACE, highlightthickness=0)
        self.canvas.pack(side='left', padx=(8, 4))
        self.bar_rect = self.canvas.create_rectangle(0, 0, 0, 12, fill=GREEN, width=0)

        self.lbl_status = tk.Label(self, text='', bg=BG,
                                   font=('Consolas', 8, 'bold'), width=10)
        self.lbl_status.pack(side='left', padx=2)

        # can_grow info
        enc = item.get('encoding', '')
        can_grow = enc in ('java-mutf8', 'len2le-utf8', 'len1-utf8')
        grow_txt = '(length-prefix: có thể dài hơn)' if can_grow else '(fixed slot: truncate nếu dài hơn)'
        tk.Label(self, text=grow_txt, bg=BG, fg=SURFACE2,
                 font=('Consolas', 7)).pack(side='left', padx=4)

        self.update_meter(item['original'])   # initial render

    def update_meter(self, new_text: str):
        orig_b, new_b, limit_b, can_grow = _calc_byte_sizes(self.item, new_text)

        self.lbl_orig.config(text=f'{orig_b} B')
        self.lbl_new.config(text=f'{new_b} B')
        self.lbl_limit.config(text=f'{limit_b} B')

        # Fill ratio
        ratio = min(new_b / limit_b, 1.0) if limit_b > 0 else 0.0
        fill_w = int(self.BAR_W * ratio)

        if new_b > limit_b:
            color = RED
        elif new_b == orig_b:
            color = BLUE
        elif new_b > orig_b:
            color = YELLOW if can_grow else PEACH
        else:
            color = GREEN

        self.canvas.coords(self.bar_rect, 0, 0, fill_w, 12)
        self.canvas.itemconfig(self.bar_rect, fill=color)
        self.lbl_new.config(fg=color)

        if new_b > limit_b and not can_grow:
            status = '⚠ OVERFLOW'
            sc     = RED
        elif new_b > limit_b and can_grow:
            status = '✔ OK (grow)'
            sc     = GREEN
        elif new_b == orig_b:
            status = '= Bằng gốc'
            sc     = BLUE
        elif new_b < orig_b:
            status = f'↓ {orig_b - new_b} B'
            sc     = GREEN
        else:
            status = f'↑ {new_b - orig_b} B'
            sc     = YELLOW if can_grow else PEACH
        self.lbl_status.config(text=status, fg=sc)


# ── Main application window ───────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Binary String Translator — JAR edition')
        self.geometry('1200x780')
        self.configure(bg=BG)
        self.resizable(True, True)

        self.jar_path      = tk.StringVar()
        self.out_path      = tk.StringVar()
        self.scan_noext    = tk.BooleanVar(value=True)
        self.accent_var    = tk.BooleanVar(value=True)
        self.search_var    = tk.StringVar()
        self.replace_var   = tk.StringVar()

        self.all_strings   = []
        self.filtered      = []
        self.current_page  = 0
        self._stop_translate = False

        self._build_ui()

    # ─── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TFrame',     background=BG)
        style.configure('TLabel',     background=BG, foreground=FG,
                        font=('Segoe UI', 9))
        style.configure('TButton',    background=SURFACE, foreground=FG,
                        font=('Segoe UI', 9), relief='flat', padding=4)
        style.map('TButton',          background=[('active', SURFACE2)])
        style.configure('Accent.TButton', background=BLUE, foreground=BG,
                        font=('Segoe UI', 9, 'bold'))
        style.map('Accent.TButton',   background=[('active', LBLUE)])
        style.configure('TEntry',     fieldbackground=SURFACE, foreground=FG,
                        insertcolor=FG)
        style.configure('TCheckbutton', background=BG, foreground=FG)
        style.configure('TProgressbar', troughcolor=SURFACE, background=BLUE)
        style.configure('Treeview',   background=BG2, fieldbackground=BG2,
                        foreground=FG, rowheight=22, font=('Segoe UI', 9))
        style.configure('Treeview.Heading', background=SURFACE,
                        foreground=BLUE, font=('Segoe UI', 9, 'bold'))
        style.map('Treeview',         background=[('selected', SURFACE2)])

        # ── Row 1: JAR path ─────────────────────────────────────────────────
        top = ttk.Frame(self, padding=(8, 6))
        top.pack(fill='x')
        ttk.Label(top, text='JAR:').pack(side='left')
        ttk.Entry(top, textvariable=self.jar_path, width=52).pack(side='left', padx=4)
        ttk.Button(top, text='Browse…', command=self._browse_jar).pack(side='left')
        ttk.Button(top, text='🔍 Scan', style='Accent.TButton',
                   command=self._start_scan).pack(side='left', padx=8)
        ttk.Checkbutton(top, text='Quét file không extension',
                        variable=self.scan_noext).pack(side='left', padx=4)
        self.enc_info_var = tk.StringVar(value='')
        tk.Label(top, textvariable=self.enc_info_var, bg=BG, fg=GREEN,
                 font=('Segoe UI', 8)).pack(side='left', padx=6)

        # ── Row 2: Output ────────────────────────────────────────────────────
        row2 = ttk.Frame(self, padding=(8, 2))
        row2.pack(fill='x')
        ttk.Label(row2, text='Output:').pack(side='left')
        ttk.Entry(row2, textvariable=self.out_path, width=52).pack(side='left', padx=4)
        ttk.Button(row2, text='Browse…', command=self._browse_out).pack(side='left')
        ttk.Button(row2, text='🔧 Patch JAR', style='Accent.TButton',
                   command=self._patch_jar).pack(side='left', padx=16)

        # ── Row 3: Translate ─────────────────────────────────────────────────
        ctrl = ttk.Frame(self, padding=(8, 2))
        ctrl.pack(fill='x')
        ttk.Checkbutton(ctrl, text='Có dấu', variable=self.accent_var).pack(side='left')
        ttk.Button(ctrl, text='▶ Dịch tất cả',
                   command=self._translate_all).pack(side='left', padx=6)
        ttk.Button(ctrl, text='▶ Dịch trang này',
                   command=self._translate_page).pack(side='left')
        ttk.Button(ctrl, text='■ Dừng',
                   command=self._stop_translation).pack(side='left', padx=4)

        # ── Row 4: Search & Replace ──────────────────────────────────────────
        sr = ttk.Frame(self, padding=(8, 2))
        sr.pack(fill='x')
        ttk.Label(sr, text='Search:').pack(side='left')
        ttk.Entry(sr, textvariable=self.search_var, width=26).pack(side='left', padx=(2, 0))
        CopyButton(sr, self.search_var.get).pack(side='left', padx=(1, 6))
        ttk.Label(sr, text='Replace:').pack(side='left')
        ttk.Entry(sr, textvariable=self.replace_var, width=26).pack(side='left', padx=(2, 0))
        paste_btn = tk.Label(sr, text='⬇', cursor='hand2',
                             font=('Segoe UI', 8), fg=GREEN, bg=BG, padx=2)
        paste_btn.pack(side='left', padx=(1, 4))
        paste_btn.bind('<Button-1>', self._paste_to_replace)
        paste_btn.bind('<Enter>',    lambda e: paste_btn.config(fg=LBLUE))
        paste_btn.bind('<Leave>',    lambda e: paste_btn.config(fg=GREEN))
        ttk.Button(sr, text='Replace All', command=self._replace_all).pack(side='left', padx=2)
        ttk.Button(sr, text='Filter',      command=self._apply_filter).pack(side='left', padx=2)
        ttk.Button(sr, text='Clear',       command=self._clear_filter).pack(side='left', padx=2)

        # ── Row 5: Status ────────────────────────────────────────────────────
        stat = ttk.Frame(self, padding=(8, 2))
        stat.pack(fill='x')
        self.status_var = tk.StringVar(value='Sẵn sàng.')
        ttk.Label(stat, textvariable=self.status_var).pack(side='left')
        self.progress = ttk.Progressbar(stat, length=280, mode='determinate')
        self.progress.pack(side='left', padx=10)
        self.count_var = tk.StringVar(value='0 strings')
        ttk.Label(stat, textvariable=self.count_var).pack(side='left')

        # ── Treeview ─────────────────────────────────────────────────────────
        tf = ttk.Frame(self)
        tf.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('enabled', 'entry', 'offset', 'encoding',
                'original', 'cp_orig', 'translated', 'cp_trans')
        self.tree = ttk.Treeview(tf, columns=cols, show='headings',
                                 selectmode='browse')
        self.tree.heading('enabled',    text='✔')
        self.tree.heading('entry',      text='JAR Entry')
        self.tree.heading('offset',     text='Offset')
        self.tree.heading('encoding',   text='Encoding')
        self.tree.heading('original',   text='Original (CN/VI)')
        self.tree.heading('cp_orig',    text='')
        self.tree.heading('translated', text='Translated (double-click to edit)')
        self.tree.heading('cp_trans',   text='')

        self.tree.column('enabled',    width=28,  anchor='center', stretch=False)
        self.tree.column('entry',      width=180, stretch=False)
        self.tree.column('offset',     width=80,  anchor='center', stretch=False)
        self.tree.column('encoding',   width=90,  anchor='center', stretch=False)
        self.tree.column('original',   width=250)
        self.tree.column('cp_orig',    width=22,  anchor='center', stretch=False)
        self.tree.column('translated', width=280)
        self.tree.column('cp_trans',   width=22,  anchor='center', stretch=False)

        vsb = ttk.Scrollbar(tf, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')

        self.tree.bind('<Double-1>', self._on_double_click)
        self.tree.bind('<Button-1>', self._on_click)

        # ── Pager ─────────────────────────────────────────────────────────────
        pager = ttk.Frame(self, padding=(8, 4))
        pager.pack(fill='x')
        ttk.Button(pager, text='◀ Prev', command=self._prev_page).pack(side='left')
        self.page_var = tk.StringVar(value='Page 0 / 0')
        ttk.Label(pager, textvariable=self.page_var).pack(side='left', padx=10)
        ttk.Button(pager, text='Next ▶', command=self._next_page).pack(side='left')

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _paste_to_replace(self, _=None):
        try:
            self.replace_var.set(self.clipboard_get())
        except Exception:
            pass

    # ─── File dialogs ─────────────────────────────────────────────────────────

    def _browse_jar(self):
        p = filedialog.askopenfilename(
            title='Chọn file JAR',
            filetypes=[('JAR files', '*.jar'), ('All files', '*.*')],
        )
        if p:
            self.jar_path.set(p)
            base, _ = os.path.splitext(p)
            self.out_path.set(base + '_vi.jar')

    def _browse_out(self):
        p = filedialog.asksaveasfilename(
            title='Lưu JAR output',
            defaultextension='.jar',
            filetypes=[('JAR files', '*.jar')],
        )
        if p:
            self.out_path.set(p)

    # ─── Scan ─────────────────────────────────────────────────────────────────

    def _start_scan(self):
        path = self.jar_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror('Lỗi', 'Chọn file JAR hợp lệ.')
            return
        self.all_strings = []
        self.filtered    = []
        self._clear_tree()
        self.enc_info_var.set('')
        self.status_var.set('Đang scan binary entries trong JAR…')
        threading.Thread(target=self._scan_thread, args=(path,),
                         daemon=True).start()

    def _scan_thread(self, path):
        def cb(i, total, name):
            self.progress['maximum'] = total
            self.progress['value']   = i
            self.status_var.set(f'Scan {i}/{total}: {os.path.basename(name)}')

        results = scan_jar(path, self.scan_noext.get(), progress_cb=cb)
        self.all_strings  = results
        self.filtered     = results[:]
        self.current_page = 0

        enc_counts: dict = {}
        for r in results:
            k = r['encoding']
            enc_counts[k] = enc_counts.get(k, 0) + 1
        enc_summary = '  '.join(f'{k}:{v}' for k, v in enc_counts.items())

        self.after(0, self._refresh_tree)
        self.after(0, lambda: self.status_var.set(
            f'Scan xong. {len(results)} strings CN/VI từ binary entries.'))
        self.after(0, lambda: self.count_var.set(f'{len(results)} strings'))
        self.after(0, lambda: self.enc_info_var.set(enc_summary))

    # ─── Tree ─────────────────────────────────────────────────────────────────

    def _refresh_tree(self):
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass
        total       = len(self.filtered)
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        self.page_var.set(f'Page {self.current_page + 1} / {total_pages}')
        start = self.current_page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, total)

        for i, item in enumerate(self.filtered[start:end]):
            check   = '☑' if item['enabled'] else '☐'
            entry   = os.path.basename(item['jar_entry'])
            offset  = f"0x{item['offset']:08X}"
            enc     = item['encoding']
            orig    = item['original'][:68]
            trans_v = item['translated'] or item['original']
            item['translated'] = trans_v
            trans   = trans_v[:68]
            tag     = 'translated' if trans_v != item['original'] else 'normal'
            iid     = f'row_{start + i}'
            self.tree.insert('', 'end', iid=iid,
                             values=(check, entry, offset, enc, orig, '⧉', trans, '⧉'),
                             tags=(tag,))

        self.tree.tag_configure('translated', foreground=GREEN)
        self.tree.tag_configure('normal',     foreground=FG)

    def _update_tree_translated(self):
        start = self.current_page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, len(self.filtered))
        for i, item in enumerate(self.filtered[start:end]):
            iid = f'row_{start + i}'
            if not self.tree.exists(iid):
                continue
            trans_v = item['translated'] or item['original']
            item['translated'] = trans_v
            tag = 'translated' if trans_v != item['original'] else 'normal'
            self.tree.set(iid, 'translated', trans_v[:68])
            self.tree.item(iid, tags=(tag,))

    def _clear_tree(self):
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass

    # ─── Paging ───────────────────────────────────────────────────────────────

    def _prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self._refresh_tree()

    def _next_page(self):
        total_pages = max(1, (len(self.filtered) + PAGE_SIZE - 1) // PAGE_SIZE)
        if self.current_page < total_pages - 1:
            self.current_page += 1
            self._refresh_tree()

    # ─── Click handlers ───────────────────────────────────────────────────────

    def _on_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region != 'cell':
            return
        col = self.tree.identify_column(event.x)
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        row_num = int(iid.split('_')[1])
        if row_num >= len(self.filtered):
            return
        item = self.filtered[row_num]

        if col == '#1':    # toggle enabled
            item['enabled'] = not item['enabled']
            self.tree.set(iid, 'enabled', '☑' if item['enabled'] else '☐')
        elif col == '#6':  # copy original
            self.clipboard_clear()
            self.clipboard_append(item['original'])
        elif col == '#8':  # copy translated
            self.clipboard_clear()
            self.clipboard_append(item['translated'] or item['original'])

    def _on_double_click(self, event):
        """Open an inline edit popup with a live byte-size meter."""
        col = self.tree.identify_column(event.x)
        iid = self.tree.identify_row(event.y)
        if not iid or col != '#7':   # only translated column
            return
        row_num = int(iid.split('_')[1])
        if row_num >= len(self.filtered):
            return
        item = self.filtered[row_num]

        bbox = self.tree.bbox(iid, column='translated')
        if not bbox:
            return
        x, y, w, h = bbox

        # ── Popup container ──────────────────────────────────────────────────
        popup = tk.Toplevel(self)
        popup.title('Sửa bản dịch')
        popup.configure(bg=BG)
        popup.resizable(True, False)

        # Position popup just below the selected row
        tx = self.tree.winfo_rootx() + x
        ty = self.tree.winfo_rooty() + y + h + 2
        popup.geometry(f'+{tx}+{ty}')
        popup.grab_set()

        # ── Header: show original ────────────────────────────────────────────
        hdr = tk.Frame(popup, bg=BG, pady=4)
        hdr.pack(fill='x', padx=8)
        tk.Label(hdr, text='Gốc:', bg=BG, fg=YELLOW,
                 font=('Segoe UI', 9, 'bold')).pack(side='left')
        tk.Label(hdr, text=item['original'], bg=BG, fg=FG,
                 font=('Segoe UI', 9), wraplength=600,
                 justify='left').pack(side='left', padx=6)

        # Encoding / offset info
        info_txt = (f"  [{item['encoding']}  offset 0x{item['offset']:08X}"
                    f"  JAR: {item['jar_entry']}]")
        tk.Label(hdr, text=info_txt, bg=BG, fg=SURFACE2,
                 font=('Consolas', 7)).pack(side='left', padx=4)

        # ── Entry field ──────────────────────────────────────────────────────
        ef = tk.Frame(popup, bg=BG)
        ef.pack(fill='x', padx=8, pady=(0, 2))
        tk.Label(ef, text='Dịch:', bg=BG, fg=GREEN,
                 font=('Segoe UI', 9, 'bold')).pack(side='left')
        entry_var = tk.StringVar(value=item['translated'] or item['original'])
        entry = ttk.Entry(ef, textvariable=entry_var, font=('Segoe UI', 10), width=60)
        entry.pack(side='left', padx=6, fill='x', expand=True)
        entry.select_range(0, 'end')
        entry.focus_set()

        # ── Byte meter ───────────────────────────────────────────────────────
        meter = ByteMeter(popup, item)
        meter.pack(fill='x', padx=8, pady=2)

        # Live update
        def on_key(*_):
            meter.update_meter(entry_var.get())

        entry_var.trace_add('write', on_key)

        # ── Buttons ──────────────────────────────────────────────────────────
        bf = tk.Frame(popup, bg=BG, pady=4)
        bf.pack(fill='x', padx=8)

        def save_and_close(_=None):
            new_val = entry_var.get()
            item['translated'] = new_val
            tag = 'translated' if new_val != item['original'] else 'normal'
            self.tree.set(iid, 'translated', new_val[:68])
            self.tree.item(iid, tags=(tag,))
            popup.destroy()

        def cancel(_=None):
            popup.destroy()

        ttk.Button(bf, text='✔ Lưu (Enter)', style='Accent.TButton',
                   command=save_and_close).pack(side='left', padx=4)
        ttk.Button(bf, text='✘ Hủy (Esc)',
                   command=cancel).pack(side='left', padx=4)

        # Reset to original
        def reset(_=None):
            entry_var.set(item['original'])
            meter.update_meter(item['original'])

        ttk.Button(bf, text='↺ Reset về gốc',
                   command=reset).pack(side='left', padx=4)

        entry.bind('<Return>', save_and_close)
        entry.bind('<Escape>', cancel)

    # ─── Translation ──────────────────────────────────────────────────────────

    def _translate_all(self):
        if not self.all_strings:
            messagebox.showinfo('Thông báo', 'Chưa scan JAR.')
            return
        self._stop_translate = False
        threading.Thread(target=self._translate_thread,
                         args=(self.all_strings, list(range(len(self.all_strings)))),
                         daemon=True).start()

    def _translate_page(self):
        if not self.filtered:
            return
        self._stop_translate = False
        start = self.current_page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, len(self.filtered))
        threading.Thread(target=self._translate_thread,
                         args=(self.filtered, list(range(start, end))),
                         daemon=True).start()

    def _stop_translation(self):
        self._stop_translate = True
        self.status_var.set('Đã dừng dịch.')

    def _safe_refresh(self):
        try:
            self._update_tree_translated()
        except Exception:
            pass

    def _translate_thread(self, items, indices):
        total = len(indices)

        def cb(n, _):
            self.progress['maximum'] = total
            self.progress['value']   = n
            self.status_var.set(f'Đang dịch {n}/{total}…')
            if n % 5 == 0:
                self.after(0, self._safe_refresh)

        translate_batch(items, indices, self.accent_var.get(),
                        progress_cb=cb, stop_flag=lambda: self._stop_translate)
        self.after(0, self._refresh_tree)
        self.after(0, lambda: self.status_var.set(f'Dịch xong {total} strings.'))

    # ─── Search & Replace ─────────────────────────────────────────────────────

    def _apply_filter(self):
        q = self.search_var.get().lower().strip()
        if not q:
            self.filtered = self.all_strings[:]
        else:
            self.filtered = [
                x for x in self.all_strings
                if q in x['original'].lower()
                or q in (x['translated'] or '').lower()
                or q in x['jar_entry'].lower()
            ]
        self.current_page = 0
        self.count_var.set(f'{len(self.filtered)} strings')
        self._refresh_tree()

    def _clear_filter(self):
        self.search_var.set('')
        self.filtered     = self.all_strings[:]
        self.current_page = 0
        self.count_var.set(f'{len(self.filtered)} strings')
        self._refresh_tree()

    def _replace_all(self):
        q = self.search_var.get()
        r = self.replace_var.get()
        if not q:
            messagebox.showinfo('Thông báo', 'Nhập từ cần tìm.')
            return
        count = sum(1 for it in self.filtered if q in (it['translated'] or ''))
        for it in self.filtered:
            if it['translated'] and q in it['translated']:
                it['translated'] = it['translated'].replace(q, r)
        self._refresh_tree()
        messagebox.showinfo('Replace All', f'Đã replace {count} strings.')

    # ─── Patch ────────────────────────────────────────────────────────────────

    def _patch_jar(self):
        src = self.jar_path.get().strip()
        dst = self.out_path.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showerror('Lỗi', 'File JAR nguồn không hợp lệ.')
            return
        if not dst:
            messagebox.showerror('Lỗi', 'Chưa chọn file output.')
            return
        changed = sum(
            1 for x in self.all_strings
            if x['enabled'] and x['translated'] != x['original']
        )
        if changed == 0:
            messagebox.showinfo('Thông báo', 'Không có string nào thay đổi.')
            return
        if not messagebox.askyesno('Xác nhận',
                                   f'Patch {changed} strings → {dst}\n\nTiếp tục?'):
            return
        self.status_var.set('Đang patch…')
        threading.Thread(target=self._patch_thread, args=(src, dst),
                         daemon=True).start()

    def _patch_thread(self, src, dst):
        def cb(i, total, name):
            self.progress['maximum'] = total
            self.progress['value']   = i
            self.status_var.set(f'Packing {i}/{total}: {os.path.basename(name)}')

        try:
            patch_jar(src, dst, self.all_strings, progress_cb=cb)
            self.after(0, lambda: messagebox.showinfo(
                'Xong', f'Patch thành công!\nOutput: {dst}'))
            self.after(0, lambda: self.status_var.set(f'Patch xong → {dst}'))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror('Lỗi patch', str(e)))
            self.after(0, lambda: self.status_var.set('Lỗi patch.'))


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    if not TRANSLATOR_OK:
        print('WARNING: pip install deep-translator unidecode')
    app = App()
    app.mainloop()
