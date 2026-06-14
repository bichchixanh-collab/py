#!/usr/bin/env python3
"""
JAR String Translator
Scan, translate, and patch Chinese/Vietnamese string constants in Java .class files inside a .jar
Patch method: direct UTF8 constant pool modification (no JDK required)
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

# ─────────────────────────────────────────────
# Java Class File Parser / Patcher
# ─────────────────────────────────────────────

CONSTANT_Utf8               = 1
CONSTANT_Integer            = 3
CONSTANT_Float              = 4
CONSTANT_Long               = 5
CONSTANT_Double             = 6
CONSTANT_Class              = 7
CONSTANT_String             = 8
CONSTANT_Fieldref           = 9
CONSTANT_Methodref          = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_NameAndType        = 12
CONSTANT_MethodHandle       = 15
CONSTANT_MethodType         = 16
CONSTANT_InvokeDynamic      = 18

TAG_SIZE = {
    CONSTANT_Integer: 4, CONSTANT_Float: 4,
    CONSTANT_Long: 8,    CONSTANT_Double: 8,
    CONSTANT_Class: 2,   CONSTANT_String: 2,
    CONSTANT_Fieldref: 4, CONSTANT_Methodref: 4,
    CONSTANT_InterfaceMethodref: 4, CONSTANT_NameAndType: 4,
    CONSTANT_MethodHandle: 3, CONSTANT_MethodType: 2,
    CONSTANT_InvokeDynamic: 4,
}

# ── Chỉ nhận ký tự Hán thực sự (CJK Unified + Extension A/B + Compatibility)
# KHÔNG bao gồm: CJK Symbols/Punctuation, Fullwidth Forms, Hiragana, Katakana
# vì chúng có thể xuất hiện trong string tiếng Anh của game
RE_CHINESE = re.compile(
    r'[\u4e00-\u9fff'   # CJK Unified Ideographs (phần lớn chữ Hán thông dụng)
    r'\u3400-\u4dbf'    # CJK Extension A
    r'\uf900-\ufaff]'   # CJK Compatibility Ideographs
)

# ── Chỉ nhận ký tự ĐẶC TRƯNG tiếng Việt - không xuất hiện trong ngôn ngữ Latin khác
# KHÔNG bao gồm: à á â ã è é ê ì í ò ó ô ú ý (có trong Pháp/Bồ/Tây Ban Nha)
RE_VIETNAMESE = re.compile(
    r'[ăắằẳẵặĂẮẰẲẴẶ'   # a với dấu mũ ngắn
    r'ơớờởỡợƠỚỜỞỠỢ'    # o với móc
    r'ưứừửữựƯỨỪỬỮỰ'    # u với móc
    r'đĐ'                # d gạch ngang
    r'ấầẩẫậẤẦẨẪẬ'       # â + thanh (trừ â không dấu - có trong tiếng Pháp)
    r'ếềểễệẾỀỂỄỆ'       # ê + thanh
    r'ốồổỗộỐỒỔỖỘ'       # ô + thanh
    r'ỉịỈỊ'              # i với dấu hỏi/nặng
    r'ọỏỌỎ'              # o với dấu nặng/hỏi
    r'ụủỤỦ'              # u với dấu nặng/hỏi
    r'ỳỵỷỹỲỴỶỸ]'        # y với dấu
)


def has_chinese(s: str) -> bool:
    return bool(RE_CHINESE.search(s))

def has_vietnamese(s: str) -> bool:
    return bool(RE_VIETNAMESE.search(s))

def has_target_language(s: str) -> bool:
    """
    Chỉ trả về True nếu string chứa ký tự Hán HOẶC ký tự tiếng Việt đặc trưng.
    String thuần ASCII/Latin/tiếng Anh bị loại hoàn toàn.
    """
    s = s.strip()
    if not s:
        return False
    return has_chinese(s) or has_vietnamese(s)


def parse_constant_pool(data: bytes):
    if data[:4] != b'\xca\xfe\xba\xbe':
        return None, 0
    pos = 8
    count = struct.unpack_from('>H', data, pos)[0]
    pos += 2
    pool = [None]
    i = 1
    while i < count:
        tag = data[pos]
        entry_start = pos
        pos += 1
        if tag == CONSTANT_Utf8:
            length = struct.unpack_from('>H', data, pos)[0]
            pos += 2
            raw = data[pos:pos+length]
            pos += length
            pool.append((tag, raw, entry_start, 3 + length))
        elif tag in (CONSTANT_Long, CONSTANT_Double):
            pool.append((tag, data[pos:pos+8], entry_start, 9))
            pool.append(None)
            pos += 8
            i += 1
        elif tag in TAG_SIZE:
            sz = TAG_SIZE[tag]
            pool.append((tag, data[pos:pos+sz], entry_start, 1 + sz))
            pos += sz
        else:
            return None, 0
        i += 1
    return pool, pos


def extract_strings_from_class(data: bytes):
    """Chỉ extract string tiếng Trung hoặc tiếng Việt từ constant pool."""
    pool, _ = parse_constant_pool(data)
    if pool is None:
        return []
    results = []
    for idx, entry in enumerate(pool):
        if entry is None:
            continue
        tag, raw, *_ = entry
        if tag != CONSTANT_Utf8:
            continue
        try:
            text = raw.decode('utf-8')
        except Exception:
            continue
        if has_target_language(text):
            results.append((idx, text))
    return results


def patch_class_strings(data: bytes, replacements: dict) -> bytes:
    pool, after_pool = parse_constant_pool(data)
    if pool is None:
        return data

    new_cp_bytes = BytesIO()
    modified = False

    for idx, entry in enumerate(pool):
        if idx == 0:
            continue
        if entry is None:
            continue
        tag, raw, entry_start, entry_len = entry

        if tag == CONSTANT_Utf8 and idx in replacements:
            new_text = replacements[idx]
            try:
                new_raw = new_text.encode('utf-8')
            except Exception:
                new_raw = raw
            new_cp_bytes.write(bytes([CONSTANT_Utf8]))
            new_cp_bytes.write(struct.pack('>H', len(new_raw)))
            new_cp_bytes.write(new_raw)
            if new_raw != raw:
                modified = True
        else:
            new_cp_bytes.write(data[entry_start:entry_start + entry_len])

    if not modified:
        return data

    header = data[:8]
    cp_count = struct.pack('>H', len(pool))
    rest = data[after_pool:]
    return header + cp_count + new_cp_bytes.getvalue() + rest


# ─────────────────────────────────────────────
# JAR / No-Extension Scanner
# ─────────────────────────────────────────────

def is_class_data(data: bytes) -> bool:
    return data[:4] == b'\xca\xfe\xba\xbe'


def scan_jar(jar_path: str, scan_noext: bool, progress_cb=None):
    results = []
    with zipfile.ZipFile(jar_path, 'r') as zf:
        all_entries = zf.namelist()
        entries = []
        for n in all_entries:
            basename = os.path.basename(n)
            if n.endswith('.class'):
                entries.append(n)
            elif scan_noext and basename and '.' not in basename:
                entries.append(n)

        total = len(entries)
        for i, name in enumerate(entries):
            if progress_cb:
                progress_cb(i + 1, total, name)
            try:
                data = zf.read(name)
                if not is_class_data(data):
                    continue
                strings = extract_strings_from_class(data)
                for cp_idx, text in strings:
                    results.append({
                        'jar_entry': name,
                        'cp_index': cp_idx,
                        'original': text,
                        'translated': text,
                        'enabled': True,
                    })
            except Exception:
                continue
    return results


def patch_jar(jar_path: str, out_path: str, string_list: list, progress_cb=None):
    entry_replacements = {}
    for item in string_list:
        if not item['enabled']:
            continue
        if item['translated'] == item['original']:
            continue
        ent = item['jar_entry']
        if ent not in entry_replacements:
            entry_replacements[ent] = {}
        entry_replacements[ent][item['cp_index']] = item['translated']

    with zipfile.ZipFile(jar_path, 'r') as zin:
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            names = zin.namelist()
            total = len(names)
            for i, name in enumerate(names):
                if progress_cb:
                    progress_cb(i + 1, total, name)
                data = zin.read(name)
                if name in entry_replacements:
                    try:
                        data = patch_class_strings(data, entry_replacements[name])
                    except Exception as e:
                        print(f"Patch error {name}: {e}")
                zout.writestr(zipfile.ZipInfo(name), data)


# ─────────────────────────────────────────────
# Translation
# ─────────────────────────────────────────────

_translate_cache = {}
_google_translator = None

def get_translator():
    global _google_translator
    if not TRANSLATOR_OK:
        return None
    if _google_translator is None:
        # source='zh-CN': chỉ dịch tiếng Trung, không dịch tiếng Anh/Việt
        _google_translator = GoogleTranslator(source='zh-CN', target='vi')
    return _google_translator


def translate_batch(items: list, indices: list, accent: bool, progress_cb=None, stop_flag=None):
    tr = get_translator()
    if tr is None:
        return
    total = len(indices)
    for n, idx in enumerate(indices):
        if stop_flag and stop_flag():
            break
        item = items[idx]
        src_text = item['original']

        # Chỉ dịch string có ký tự Hán — bỏ qua tiếng Việt và tiếng Anh
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

            # Guard: translate() có thể trả về None
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


# ─────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────

PAGE_SIZE = 200

class CopyButton(tk.Label):
    """Small inline copy button."""
    def __init__(self, parent, get_text_fn, **kwargs):
        super().__init__(parent, text="⧉", cursor="hand2",
                         font=('Segoe UI', 8), fg='#89b4fa', bg='#1e1e2e',
                         padx=2, pady=0, **kwargs)
        self.get_text_fn = get_text_fn
        self.bind('<Button-1>', self._copy)
        self.bind('<Enter>', lambda e: self.config(fg='#74c7ec'))
        self.bind('<Leave>', lambda e: self.config(fg='#89b4fa'))

    def _copy(self, _=None):
        text = self.get_text_fn()
        self.clipboard_clear()
        self.clipboard_append(text)
        orig = self.cget('text')
        self.config(text='✓', fg='#a6e3a1')
        self.after(800, lambda: self.config(text='⧉', fg='#89b4fa'))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("JAR String Translator")
        self.geometry("1140x740")
        self.configure(bg="#1e1e2e")
        self.resizable(True, True)

        self.jar_path = tk.StringVar()
        self.out_path = tk.StringVar()
        self.accent_var = tk.BooleanVar(value=True)
        self.scan_noext_var = tk.BooleanVar(value=False)
        self.search_var = tk.StringVar()
        self.replace_var = tk.StringVar()

        self.all_strings = []
        self.filtered = []
        self.current_page = 0
        self._stop_translate = False

        self._build_ui()

    # ── UI Construction ──

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TFrame', background='#1e1e2e')
        style.configure('TLabel', background='#1e1e2e', foreground='#cdd6f4', font=('Segoe UI', 9))
        style.configure('TButton', background='#313244', foreground='#cdd6f4',
                        font=('Segoe UI', 9), relief='flat', padding=4)
        style.map('TButton', background=[('active', '#45475a')])
        style.configure('Accent.TButton', background='#89b4fa', foreground='#1e1e2e',
                        font=('Segoe UI', 9, 'bold'))
        style.map('Accent.TButton', background=[('active', '#74c7ec')])
        style.configure('TEntry', fieldbackground='#313244', foreground='#cdd6f4',
                        insertcolor='#cdd6f4')
        style.configure('TCheckbutton', background='#1e1e2e', foreground='#cdd6f4')
        style.configure('TProgressbar', troughcolor='#313244', background='#89b4fa')
        style.configure('Treeview', background='#181825', fieldbackground='#181825',
                        foreground='#cdd6f4', rowheight=22, font=('Segoe UI', 9))
        style.configure('Treeview.Heading', background='#313244', foreground='#89b4fa',
                        font=('Segoe UI', 9, 'bold'))
        style.map('Treeview', background=[('selected', '#45475a')])

        # ── Row 1: JAR path ──
        top = ttk.Frame(self, padding=(8, 6))
        top.pack(fill='x')
        ttk.Label(top, text="JAR:").pack(side='left')
        ttk.Entry(top, textvariable=self.jar_path, width=52).pack(side='left', padx=4)
        ttk.Button(top, text="Browse…", command=self._browse_jar).pack(side='left')
        ttk.Button(top, text="🔍 Scan", style='Accent.TButton',
                   command=self._start_scan).pack(side='left', padx=8)
        ttk.Checkbutton(top, text="Quét file không extension",
                        variable=self.scan_noext_var).pack(side='left', padx=4)

        # ── Row 2: Output path ──
        row2 = ttk.Frame(self, padding=(8, 2))
        row2.pack(fill='x')
        ttk.Label(row2, text="Output:").pack(side='left')
        ttk.Entry(row2, textvariable=self.out_path, width=52).pack(side='left', padx=4)
        ttk.Button(row2, text="Browse…", command=self._browse_out).pack(side='left')
        ttk.Button(row2, text="🔧 Patch JAR", style='Accent.TButton',
                   command=self._patch_jar).pack(side='left', padx=16)

        # ── Row 3: Translate controls ──
        ctrl = ttk.Frame(self, padding=(8, 2))
        ctrl.pack(fill='x')
        ttk.Checkbutton(ctrl, text="Có dấu", variable=self.accent_var).pack(side='left')
        ttk.Button(ctrl, text="▶ Dịch tất cả", command=self._translate_all).pack(side='left', padx=6)
        ttk.Button(ctrl, text="▶ Dịch trang này", command=self._translate_page).pack(side='left')
        ttk.Button(ctrl, text="■ Dừng", command=self._stop_translation).pack(side='left', padx=4)

        # ── Row 4: Search & Replace ──
        sr = ttk.Frame(self, padding=(8, 2))
        sr.pack(fill='x')

        ttk.Label(sr, text="Search:").pack(side='left')
        self.search_entry = ttk.Entry(sr, textvariable=self.search_var, width=26)
        self.search_entry.pack(side='left', padx=(2, 0))
        CopyButton(sr, lambda: self.search_var.get()).pack(side='left', padx=(1, 6))

        ttk.Label(sr, text="Replace:").pack(side='left')
        self.replace_entry = ttk.Entry(sr, textvariable=self.replace_var, width=26)
        self.replace_entry.pack(side='left', padx=(2, 0))

        paste_btn = tk.Label(sr, text="⬇", cursor="hand2", font=('Segoe UI', 8),
                             fg='#a6e3a1', bg='#1e1e2e', padx=2)
        paste_btn.pack(side='left', padx=(1, 4))
        paste_btn.bind('<Button-1>', self._paste_to_replace)
        paste_btn.bind('<Enter>', lambda e: paste_btn.config(fg='#74c7ec'))
        paste_btn.bind('<Leave>', lambda e: paste_btn.config(fg='#a6e3a1'))

        ttk.Button(sr, text="Replace All", command=self._replace_all).pack(side='left', padx=2)
        ttk.Button(sr, text="Filter", command=self._apply_filter).pack(side='left', padx=2)
        ttk.Button(sr, text="Clear", command=self._clear_filter).pack(side='left', padx=2)

        # ── Row 5: Status ──
        stat = ttk.Frame(self, padding=(8, 2))
        stat.pack(fill='x')
        self.status_var = tk.StringVar(value="Sẵn sàng.")
        ttk.Label(stat, textvariable=self.status_var).pack(side='left')
        self.progress = ttk.Progressbar(stat, length=280, mode='determinate')
        self.progress.pack(side='left', padx=10)
        self.count_var = tk.StringVar(value="0 strings")
        ttk.Label(stat, textvariable=self.count_var).pack(side='left')

        # ── Treeview ──
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('enabled', 'class', 'original', 'cp_orig', 'translated', 'cp_trans')
        self.tree = ttk.Treeview(tree_frame, columns=cols, show='headings', selectmode='browse')
        self.tree.heading('enabled',    text='✔')
        self.tree.heading('class',      text='Class file')
        self.tree.heading('original',   text='Original (CN/VI)')
        self.tree.heading('cp_orig',    text='')
        self.tree.heading('translated', text='Translated (editable)')
        self.tree.heading('cp_trans',   text='')
        self.tree.column('enabled',    width=28,  anchor='center', stretch=False)
        self.tree.column('class',      width=190, stretch=False)
        self.tree.column('original',   width=310)
        self.tree.column('cp_orig',    width=22,  anchor='center', stretch=False)
        self.tree.column('translated', width=310)
        self.tree.column('cp_trans',   width=22,  anchor='center', stretch=False)

        vsb = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')

        self.tree.bind('<Double-1>', self._on_double_click)
        self.tree.bind('<Button-1>', self._on_click)

        # ── Pager ──
        pager = ttk.Frame(self, padding=(8, 4))
        pager.pack(fill='x')
        ttk.Button(pager, text="◀ Prev", command=self._prev_page).pack(side='left')
        self.page_var = tk.StringVar(value="Page 0 / 0")
        ttk.Label(pager, textvariable=self.page_var).pack(side='left', padx=10)
        ttk.Button(pager, text="Next ▶", command=self._next_page).pack(side='left')

    # ── Clipboard helpers ──

    def _copy_text(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _paste_to_replace(self, _=None):
        try:
            text = self.clipboard_get()
            self.replace_var.set(text)
        except Exception:
            pass

    # ── File dialogs ──

    def _browse_jar(self):
        p = filedialog.askopenfilename(filetypes=[("JAR files", "*.jar"), ("All", "*.*")])
        if p:
            self.jar_path.set(p)
            base, _ = os.path.splitext(p)
            self.out_path.set(base + "_vi.jar")

    def _browse_out(self):
        p = filedialog.asksaveasfilename(defaultextension=".jar",
                                          filetypes=[("JAR files", "*.jar")])
        if p:
            self.out_path.set(p)

    # ── Scan ──

    def _start_scan(self):
        path = self.jar_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Lỗi", "Chọn file JAR hợp lệ.")
            return
        self.all_strings = []
        self.filtered = []
        self._clear_tree()
        self.status_var.set("Đang scan...")
        threading.Thread(target=self._scan_thread,
                         args=(path, self.scan_noext_var.get()), daemon=True).start()

    def _scan_thread(self, path, scan_noext):
        def cb(i, total, name):
            self.progress['maximum'] = total
            self.progress['value'] = i
            self.status_var.set(f"Scan {i}/{total}: {os.path.basename(name)}")

        results = scan_jar(path, scan_noext, progress_cb=cb)
        self.all_strings = results
        self.filtered = results[:]
        self.current_page = 0
        self.after(0, self._refresh_tree)
        self.after(0, lambda: self.status_var.set(
            f"Scan xong. {len(results)} strings CN/VI từ {os.path.basename(path)}"))
        self.after(0, lambda: self.count_var.set(f"{len(results)} strings"))

    # ── Tree rendering ──

    def _refresh_tree(self):
        """Full rebuild of current page."""
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass
        total = len(self.filtered)
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        self.page_var.set(f"Page {self.current_page + 1} / {total_pages}")
        start = self.current_page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, total)
        for i, item in enumerate(self.filtered[start:end]):
            check = '☑' if item['enabled'] else '☐'
            cls   = os.path.basename(item['jar_entry']).replace('.class', '')
            orig  = item['original'][:70]
            # Guard: translated không bao giờ None
            trans_val = item['translated']
            if trans_val is None:
                trans_val = item['original']
                item['translated'] = trans_val
            trans = trans_val[:70]
            tag   = 'translated' if item['translated'] != item['original'] else 'normal'
            iid   = f"row_{start + i}"
            self.tree.insert('', 'end', iid=iid,
                             values=(check, cls, orig, '⧉', trans, '⧉'), tags=(tag,))
        self.tree.tag_configure('translated', foreground='#a6e3a1')
        self.tree.tag_configure('normal',     foreground='#cdd6f4')

    def _update_tree_translated(self):
        """Lightweight in-place update of translated column only."""
        start = self.current_page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, len(self.filtered))
        for i, item in enumerate(self.filtered[start:end]):
            iid = f"row_{start + i}"
            if not self.tree.exists(iid):
                continue
            trans_val = item['translated']
            if trans_val is None:
                trans_val = item['original']
                item['translated'] = trans_val
            trans = trans_val[:70]
            tag   = 'translated' if item['translated'] != item['original'] else 'normal'
            self.tree.set(iid, 'translated', trans)
            self.tree.item(iid, tags=(tag,))

    def _clear_tree(self):
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass

    # ── Paging ──

    def _prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self._refresh_tree()

    def _next_page(self):
        total_pages = max(1, (len(self.filtered) + PAGE_SIZE - 1) // PAGE_SIZE)
        if self.current_page < total_pages - 1:
            self.current_page += 1
            self._refresh_tree()

    # ── Click handlers ──

    def _on_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        col    = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if region != 'cell' or not row_id:
            return
        try:
            idx = int(row_id.replace('row_', ''))
        except ValueError:
            return

        if col == '#1':
            self.filtered[idx]['enabled'] = not self.filtered[idx]['enabled']
            self._refresh_tree()
        elif col == '#4':
            text = self.filtered[idx]['original']
            self._copy_text(text)
            self.status_var.set(f"Copied: {text[:60]}")
        elif col == '#6':
            text = self.filtered[idx]['translated'] or ''
            self._copy_text(text)
            self.status_var.set(f"Copied: {text[:60]}")

    def _on_double_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        col    = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if region != 'cell' or not row_id:
            return
        if col != '#5':
            return
        try:
            idx = int(row_id.replace('row_', ''))
        except ValueError:
            return
        bbox = self.tree.bbox(row_id, col)
        if not bbox:
            return
        x, y, w, h = bbox
        current = self.filtered[idx]['translated'] or ''
        entry = tk.Entry(self.tree, font=('Segoe UI', 9),
                         bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                         relief='flat', bd=1)
        entry.place(x=x, y=y, width=w, height=h)
        entry.insert(0, current)
        entry.focus_set()

        def save(_=None):
            new_val = entry.get()
            self.filtered[idx]['translated'] = new_val
            entry.destroy()
            self._refresh_tree()

        entry.bind('<Return>', save)
        entry.bind('<FocusOut>', save)
        entry.bind('<Escape>', lambda e: entry.destroy())

    # ── Translation ──

    def _translate_all(self):
        if not self.all_strings:
            messagebox.showinfo("Thông báo", "Chưa scan JAR.")
            return
        self._stop_translate = False
        items   = self.all_strings
        indices = list(range(len(items)))
        threading.Thread(target=self._translate_thread,
                         args=(items, indices), daemon=True).start()

    def _translate_page(self):
        if not self.filtered:
            return
        self._stop_translate = False
        start   = self.current_page * PAGE_SIZE
        end     = min(start + PAGE_SIZE, len(self.filtered))
        items   = self.filtered
        indices = list(range(start, end))
        threading.Thread(target=self._translate_thread,
                         args=(items, indices), daemon=True).start()

    def _stop_translation(self):
        self._stop_translate = True
        self.status_var.set("Đã dừng dịch.")

    def _safe_refresh(self):
        try:
            self._update_tree_translated()
        except Exception:
            pass

    def _translate_thread(self, items, indices):
        accent = self.accent_var.get()
        total  = len(indices)

        def cb(n, _tot):
            self.progress['maximum'] = total
            self.progress['value']   = n
            self.status_var.set(f"Đang dịch {n}/{total}...")
            if n % 5 == 0:
                self.after(0, self._safe_refresh)

        translate_batch(items, indices, accent,
                        progress_cb=cb,
                        stop_flag=lambda: self._stop_translate)
        self.after(0, self._refresh_tree)
        self.after(0, lambda: self.status_var.set(f"Dịch xong {total} strings."))

    # ── Search & Replace ──

    def _apply_filter(self):
        q = self.search_var.get().lower().strip()
        if not q:
            self.filtered = self.all_strings[:]
        else:
            self.filtered = [x for x in self.all_strings
                             if q in x['original'].lower() or q in (x['translated'] or '').lower()]
        self.current_page = 0
        self.count_var.set(f"{len(self.filtered)} strings")
        self._refresh_tree()

    def _clear_filter(self):
        self.search_var.set('')
        self.filtered = self.all_strings[:]
        self.current_page = 0
        self.count_var.set(f"{len(self.filtered)} strings")
        self._refresh_tree()

    def _replace_all(self):
        q = self.search_var.get()
        r = self.replace_var.get()
        if not q:
            messagebox.showinfo("Thông báo", "Nhập từ cần tìm.")
            return
        count = sum(1 for item in self.filtered if q in (item['translated'] or ''))
        for item in self.filtered:
            if item['translated'] and q in item['translated']:
                item['translated'] = item['translated'].replace(q, r)
        self._refresh_tree()
        messagebox.showinfo("Replace All", f"Đã replace {count} strings.")

    # ── Patch ──

    def _patch_jar(self):
        src = self.jar_path.get().strip()
        dst = self.out_path.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showerror("Lỗi", "File JAR nguồn không hợp lệ.")
            return
        if not dst:
            messagebox.showerror("Lỗi", "Chưa chọn file output.")
            return
        changed = sum(1 for x in self.all_strings
                      if x['enabled'] and x['translated'] != x['original'])
        if changed == 0:
            messagebox.showinfo("Thông báo", "Không có string nào thay đổi.")
            return
        if not messagebox.askyesno("Xác nhận", f"Patch {changed} strings → {dst}\n\nTiếp tục?"):
            return
        self.status_var.set("Đang patch...")
        threading.Thread(target=self._patch_thread, args=(src, dst), daemon=True).start()

    def _patch_thread(self, src, dst):
        def cb(i, total, name):
            self.progress['maximum'] = total
            self.progress['value']   = i
            self.status_var.set(f"Packing {i}/{total}: {os.path.basename(name)}")

        try:
            patch_jar(src, dst, self.all_strings, progress_cb=cb)
            self.after(0, lambda: messagebox.showinfo("Xong", f"Patch thành công!\nOutput: {dst}"))
            self.after(0, lambda: self.status_var.set(f"Patch xong → {dst}"))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Lỗi patch", str(e)))
            self.after(0, lambda: self.status_var.set("Lỗi patch."))


# ─────────────────────────────────────────────
if __name__ == '__main__':
    if not TRANSLATOR_OK:
        print("WARNING: pip install deep-translator unidecode")
    app = App()
    app.mainloop()
