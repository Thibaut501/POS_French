# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['serve.py'],
    pathex=[],
    binaries=[],
    datas=[('templates', 'templates'), ('static', 'static'), ('database', 'database')],
    hiddenimports=['waitress', 'flask', 'schedule', 'cryptography', 'cryptography.hazmat.primitives', 'cryptography.hazmat.primitives.asymmetric', 'cryptography.hazmat.primitives.asymmetric.padding', 'cryptography.hazmat.primitives.asymmetric.rsa', 'cryptography.hazmat.primitives.hashes', 'cryptography.hazmat.primitives.serialization', 'cryptography.hazmat.primitives.kdf.pbkdf2', 'cryptography.hazmat.backends', 'cryptography.fernet', 'barcode', 'pyzbar', 'PIL', 'stripe', 'sqlalchemy', 'alembic', 'pyodbc', 'email', 'smtplib', 'sqlite3', 'uuid', 'subprocess', 'platform'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='pos_v3',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='pos_v3',
)
