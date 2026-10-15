"""Work Scout: read-only Windows local disk inventory."""
import ctypes
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import queue
import string
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

EXCLUDED = {'windows', 'program files', 'program files (x86)', 'programdata', '$recycle.bin', 'system volume information', 'recovery', '$windows.~bt', '$windows.~ws', 'msocache'}
MAX_HASH_BYTES = 100 * 1024 * 1024

def drives():
    if os.name != 'nt':
        return [str(Path.home())]
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    get_type = ctypes.windll.kernel32.GetDriveTypeW
    return [f'{letter}:\\' for i, letter in enumerate(string.ascii_uppercase) if mask & (1 << i) and get_type(f'{letter}:\\') == 3]

def scan(roots, duplicates=False, progress=None):
    files, errors, excluded = [], [], []
    for root in roots:
        def onerror(exc):
            errors.append({'path': str(getattr(exc, 'filename', root)), 'error': str(exc)})
        for base, dirs, names in os.walk(root, topdown=True, onerror=onerror, followlinks=False):
            kept = []
            for name in dirs:
                path = os.path.join(base, name)
                if name.lower() in EXCLUDED or os.path.islink(path):
                    excluded.append(path)
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in names:
                path = os.path.join(base, name)
                try:
                    if os.path.islink(path):
                        continue
                    stat = os.stat(path, follow_symlinks=False)
                    files.append({'path': path, 'size': stat.st_size, 'modified': dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat(), 'extension': Path(name).suffix.lower() or '(none)'})
                except OSError as exc:
                    errors.append({'path': path, 'error': str(exc)})
                if progress and len(files) % 1000 == 0 and files:
                    progress(f'Найдено файлов: {len(files):,}')
    groups = []
    if duplicates:
        by_size = {}
        for f in files:
            if 0 < f['size'] <= MAX_HASH_BYTES:
                by_size.setdefault(f['size'], []).append(f)
        by_hash = {}
        for same_size in by_size.values():
            if len(same_size) < 2:
                continue
            for f in same_size:
                try:
                    digest = hashlib.sha256()
                    with open(f['path'], 'rb') as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(chunk)
                    by_hash.setdefault((f['size'], digest.hexdigest()), []).append(f['path'])
                except OSError as exc:
                    errors.append({'path': f['path'], 'error': str(exc)})
        groups = [paths for paths in by_hash.values() if len(paths) > 1]
    extensions = {}
    for f in files:
        item = extensions.setdefault(f['extension'], {'count': 0, 'bytes': 0})
        item['count'] += 1
        item['bytes'] += f['size']
    return {'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'roots': roots, 'files': files, 'extensions': extensions, 'duplicates': groups, 'errors': errors, 'excluded_directories': excluded, 'hash_limit_bytes': MAX_HASH_BYTES if duplicates else None}

def save_report(report, target):
    target.mkdir(parents=True, exist_ok=True)
    (target / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    ext_rows = ''.join(f'<tr><td>{html.escape(k)}</td><td>{v["count"]:,}</td><td>{v["bytes"]:,}</td></tr>' for k,v in sorted(report['extensions'].items(), key=lambda kv: -kv[1]['count']))
    page = f'''<!doctype html><html lang="ru"><meta charset="utf-8"><title>Work Scout</title><style>body{{font:16px system-ui;max-width:960px;margin:40px auto;padding:0 20px;color:#222}}table{{border-collapse:collapse;width:100%}}td,th{{padding:9px;border-bottom:1px solid #ddd;text-align:left}}.muted{{color:#666}}</style><h1>Work Scout — отчёт</h1><p class="muted">{html.escape(report['created_utc'])}</p><p><b>Файлов:</b> {len(report['files']):,} · <b>Ошибок:</b> {len(report['errors']):,} · <b>Групп дубликатов:</b> {len(report['duplicates']):,}</p><h2>Форматы</h2><table><tr><th>Расширение</th><th>Файлов</th><th>Байт</th></tr>{ext_rows}</table><p>Полные сведения находятся в report.json. Файлы не изменялись.</p></html>'''
    (target / 'report.html').write_text(page, encoding='utf-8')

class App:
    def __init__(self, root):
        self.root = root
        root.title('Work Scout v0.1')
        root.geometry('640x390')
        self.q = queue.Queue()
        self.available = drives()
        ttk.Label(root, text='Локальные диски для инвентаризации', font=('', 14, 'bold')).pack(anchor='w', padx=20, pady=(20, 8))
        self.selected = []
        for disk in self.available:
            var = tk.BooleanVar(value=True)
            ttk.Checkbutton(root, text=disk, variable=var).pack(anchor='w', padx=24)
            self.selected.append((disk, var))
        self.hashes = tk.BooleanVar(value=False)
        ttk.Checkbutton(root, text='Проверить точные дубликаты (SHA-256, файлы до 100 МБ)', variable=self.hashes).pack(anchor='w', padx=24, pady=12)
        ttk.Label(root, text='Системные папки и ссылки на каталоги пропускаются. Данные остаются локально.', wraplength=590).pack(anchor='w', padx=20)
        self.button = ttk.Button(root, text='Начать сканирование', command=self.start)
        self.button.pack(pady=15)
        self.status = tk.StringVar(value='Готово к запуску')
        ttk.Label(root, textvariable=self.status, wraplength=590).pack(padx=20)
        root.after(200, self.poll)
    def start(self):
        roots = [disk for disk, var in self.selected if var.get()]
        if not roots:
            messagebox.showwarning('Work Scout', 'Выберите хотя бы один диск')
            return
        output = filedialog.askdirectory(title='Куда сохранить отчёт?')
        if not output:
            return
        self.button.configure(state='disabled')
        check_duplicates = self.hashes.get()
        def worker():
            try:
                report = scan(roots, check_duplicates, lambda msg: self.q.put(('progress', msg)))
                folder = Path(output) / ('work-scout-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S'))
                save_report(report, folder)
                self.q.put(('done', str(folder)))
            except Exception as exc:
                self.q.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()
    def poll(self):
        try:
            while True:
                kind, value = self.q.get_nowait()
                if kind == 'progress': self.status.set(value)
                else:
                    self.button.configure(state='normal')
                    self.status.set(value)
                    messagebox.showinfo('Work Scout', 'Отчёт сохранён: ' + value) if kind == 'done' else messagebox.showerror('Ошибка', value)
        except queue.Empty:
            pass
        self.root.after(200, self.poll)

if __name__ == '__main__':
    app_root = tk.Tk()
    App(app_root)
    app_root.mainloop()
