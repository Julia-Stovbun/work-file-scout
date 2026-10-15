# Work Scout v0.1

Read-only Windows disk inventory. Selects fixed local drives; skips common Windows/system directories and directory symlinks. Reports file paths, sizes, modification timestamps, extension statistics, inaccessible paths and optionally SHA-256 duplicate groups for files up to 100 MB.

## Running

Windows: download `WorkScout.exe` from a successful GitHub Actions build artifact, run without administrator privileges, select disks and output directory. Reports are saved locally as `report.html` and `report.json`.

Python development: `python scout.py` (Tkinter required).

## Privacy

No network access, no automatic upload, no file modification. **Full report.json includes real file paths and filenames, potentially sensitive corporate information.** Keep it out of public GitHub. Only scan drives you are authorized to inspect. Antivirus may flag unsigned PyInstaller executables.

## Limitations

- Only fixed drives; mapped network drives and removable drives excluded.
- File enumeration may take time and produce large JSON reports.
- Duplicate detection reads file contents, potentially slowly; files above 100 MB are excluded from hashing.
- Windows system directory exclusion is name-based and may omit unrelated directories with the same names.
- No Excel workbook parsing or installed-program inventory yet.
