"""
Scanner - Quét chuỗi tiếng Trung trong file binary bên trong JAR

ENCODING SUPPORT:
- java-mutf8 : Embedded MUTF-8 strings trong binary records
                Format: [2-byte BE len][UTF-8 field content]
                Chỉ patch fields KHÔNG có control bytes (pure text fields)
                original_text = toàn bộ field text (CJK + ASCII suffix nếu có)
- utf-8      : UTF-8 thuần hoặc mixed binary+UTF-8 stream
- utf-16-le  : UTF-16 Little Endian
- utf-16-be  : UTF-16 Big Endian
"""

import re, zipfile, os
from typing import List, Callable, Optional
from models import StringEntry

CJK_UTF8_BYTES = re.compile(b'(?:[\xe4-\xe9][\x80-\xbf]{2})+')
CJK_TEXT_RE    = re.compile(r'[\u4e00-\u9fff]+')

ALLOWED_EXTENSIONS = {'.bin', '.dat', '.res', '.pak', '.txt', '.ini', '.cfg'}
SKIP_PREFIXES      = ('META-INF/',)
SKIP_EXTENSIONS    = ('.class',)
MIN_CHINESE_CHARS  = 1
MAX_FIELD_LEN      = 1024


def _should_process_file(name: str) -> bool:
    for p in SKIP_PREFIXES:
        if name.startswith(p):
            return False
    ext = os.path.splitext(name)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return False
    return ext == '' or ext in ALLOWED_EXTENSIONS


def _has_control(b: bytes) -> bool:
    """True nếu có control bytes (< 0x20) ngoài tab/newline/CR."""
    return any(c < 0x20 and c not in (0x09, 0x0a, 0x0d) for c in b)


# ── Encoding detection ────────────────────────────────────────────────────────

def _count_java_mutf8_strings(data: bytes) -> int:
    """
    Đếm số embedded MUTF-8 fields hợp lệ chứa CJK và không có control bytes.
    Quét từng byte (không skip theo field_len) để tìm tất cả candidates.
    """
    count = 0
    dlen  = len(data)
    for pos in range(dlen - 3):
        fl = int.from_bytes(data[pos:pos+2], 'big')
        if fl < 1 or fl > MAX_FIELD_LEN:
            continue
        end = pos + 2 + fl
        if end > dlen:
            continue
        chunk = data[pos+2:end]
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


def _detect_encoding(data: bytes, override: str = '') -> str:
    if override and override != 'auto':
        return override
    if len(data) < 4:
        return 'utf-8'
    if data[:2] == b'\xff\xfe':
        return 'utf-16-le'
    if data[:2] == b'\xfe\xff':
        return 'utf-16-be'

    # Java MUTF-8: check trước UTF-8
    if _count_java_mutf8_strings(data) >= 10:
        return 'java-mutf8'

    # CJK UTF-8 density (regex trên bytes, TRƯỚC null-ratio)
    cjk_matches = CJK_UTF8_BYTES.findall(data)
    if cjk_matches:
        cjk_total = sum(len(m) for m in cjk_matches)
        if cjk_total / len(data) > 0.05:
            valid = sum(1 for m in cjk_matches[:10]
                        if any('\u4e00' <= c <= '\u9fff'
                               for c in m.decode('utf-8', errors='replace')))
            if valid >= min(3, len(cjk_matches)):
                return 'utf-8'

    # Null-ratio → UTF-16
    null_ratio = data.count(b'\x00') / len(data)
    if null_ratio > 0.25:
        sample   = min(len(data), 1024)
        le_score = sum(1 for i in range(1, sample, 2) if data[i] == 0)
        be_score = sum(1 for i in range(0, sample, 2) if data[i] == 0)
        return 'utf-16-le' if le_score >= be_score else 'utf-16-be'

    if len(data) >= 6:
        sample = min(len(data), 512)
        cjk_le = sum(1 for i in range(1, sample, 2) if 0x4e <= data[i] <= 0x9f)
        cjk_be = sum(1 for i in range(0, sample, 2) if 0x4e <= data[i] <= 0x9f)
        if cjk_le >= 4 and cjk_le > cjk_be * 2:
            return 'utf-16-le'
        if cjk_be >= 4 and cjk_be > cjk_le * 2:
            return 'utf-16-be'

    return 'utf-8'


# ── Scan Java MUTF-8 ──────────────────────────────────────────────────────────

def _scan_java_mutf8(data: bytes, file_path: str) -> List[StringEntry]:
    """
    Tìm tất cả embedded MUTF-8 fields: [2B-BE-len][UTF-8 field]
    Chỉ lấy fields:
      - decode UTF-8 strict OK
      - có ít nhất 1 ký tự CJK
      - KHÔNG có control bytes (safe to replace)

    Entry:
      offset       = vị trí 2-byte length prefix
      byte_length  = field_len (số bytes của field content)
      original_text = toàn bộ field text (e.g. "草原5/1")
      encoding     = 'java-mutf8'
    """
    entries = []
    seen: set = set()
    dlen = len(data)

    for pos in range(dlen - 3):
        fl = int.from_bytes(data[pos:pos+2], 'big')
        if fl < 1 or fl > MAX_FIELD_LEN:
            continue
        end = pos + 2 + fl
        if end > dlen:
            continue
        chunk = data[pos+2:end]

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

        entries.append(StringEntry(
            file_path=file_path,
            offset=pos,           # vị trí prefix
            encoding='java-mutf8',
            original_text=text,   # toàn bộ field text
            byte_length=fl,       # field content length
        ))

    return entries


# ── Scan UTF-8 ────────────────────────────────────────────────────────────────

def _scan_utf8_bytes(data: bytes, file_path: str) -> List[StringEntry]:
    entries = []
    for m in CJK_UTF8_BYTES.finditer(data):
        byte_off = m.start()
        try:
            full_text = m.group(0).decode('utf-8')
        except Exception:
            continue
        for m2 in CJK_TEXT_RE.finditer(full_text):
            cjk_text = m2.group(0)
            if len(cjk_text) < 2 or '\ufffd' in cjk_text:
                continue
            cjk_bytes = cjk_text.encode('utf-8')
            sub_off   = data.find(cjk_bytes, byte_off)
            if sub_off < 0:
                continue
            entries.append(StringEntry(
                file_path=file_path,
                offset=sub_off,
                encoding='utf-8',
                original_text=cjk_text,
                byte_length=len(cjk_bytes),
            ))
    return entries


# ── Scan UTF-16 ───────────────────────────────────────────────────────────────

def _scan_utf16(data: bytes, file_path: str, enc_name: str) -> List[StringEntry]:
    enc_label = 'utf-16le' if enc_name == 'utf-16-le' else 'utf-16be'
    entries   = []
    try:
        text = data.decode(enc_name, errors='replace')
    except Exception:
        return []
    for m in CJK_TEXT_RE.finditer(text):
        raw = m.group(0)
        if len(raw) < 2 or '\ufffd' in raw:
            continue
        byte_off  = m.start() * 2
        raw_bytes = raw.encode(enc_name, errors='replace')
        if byte_off + len(raw_bytes) > len(data):
            continue
        if data[byte_off:byte_off+len(raw_bytes)] != raw_bytes:
            continue
        entries.append(StringEntry(
            file_path=file_path,
            offset=byte_off,
            encoding=enc_label,
            original_text=raw,
            byte_length=len(raw_bytes),
        ))
    return entries


# ── Scan single file ──────────────────────────────────────────────────────────

def _scan_single_file(zip_ref: zipfile.ZipFile, name: str,
                      encoding_override: str = '') -> List[StringEntry]:
    try:
        data = zip_ref.read(name)
    except Exception:
        return []
    if len(data) < 4:
        return []

    enc = _detect_encoding(data, override=encoding_override)

    if enc == 'java-mutf8':
        entries = _scan_java_mutf8(data, name)
    elif enc == 'utf-8':
        entries = _scan_utf8_bytes(data, name)
    else:
        entries = _scan_utf16(data, name, enc)

    seen: set = set()
    unique    = []
    for e in sorted(entries, key=lambda x: x.offset):
        k = (e.file_path, e.offset, e.encoding)
        if k not in seen:
            seen.add(k)
            unique.append(e)
    return unique


# ── Public JarScanner ─────────────────────────────────────────────────────────

class JarScanner:
    def __init__(self, jar_path: str,
                 progress_cb: Optional[Callable[[int, int, str], None]] = None,
                 log_cb: Optional[Callable[[str], None]] = None,
                 encoding_override: str = ''):
        self.jar_path          = jar_path
        self.progress_cb       = progress_cb
        self.log_cb            = log_cb
        self._cancelled        = False
        self.encoding_override = encoding_override

    def cancel(self):
        self._cancelled = True

    def _log(self, msg: str):
        if self.log_cb:
            self.log_cb(msg)

    def scan(self) -> List[StringEntry]:
        all_entries: List[StringEntry] = []
        try:
            with zipfile.ZipFile(self.jar_path, 'r') as zf:
                names = [n for n in zf.namelist() if _should_process_file(n)]
                total = len(names)
                self._log(f'[Scanner] {total} file cần quét')
                for idx, name in enumerate(names):
                    if self._cancelled:
                        self._log('[Scanner] Đã hủy')
                        break
                    if self.progress_cb:
                        self.progress_cb(idx + 1, total, name)
                    entries = _scan_single_file(zf, name, self.encoding_override)
                    all_entries.extend(entries)
                    if entries:
                        self._log(f'[Scanner] {name}: {len(entries)} chuỗi')
        except zipfile.BadZipFile:
            self._log('[Scanner] LỖI: File JAR không hợp lệ')
        except Exception as e:
            self._log(f'[Scanner] LỖI: {e}')
        self._log(f'[Scanner] Hoàn thành: {len(all_entries)} chuỗi')
        return all_entries
