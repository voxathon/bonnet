# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Bonnet.

Bundles the compiled Cython extensions (already built as .so under src/ by
`make all`) and, when available, the ripgrep (`rg`) binary so that
`core.binutil.resolve_rg` can find it under ``sys._MEIPASS`` at runtime. If
`rg` is not present on PATH at build time the build still succeeds -- the
server returns 503 for content search in that case.
"""

import os
import shutil
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# Compiled extensions are copied into src/ by the Makefile `pyinstaller` target
# before this spec runs (see `cd build && tar cf - *.so | (cd ../src && tar xf -)`).
src_dir = 'src'

datas = []
binaries = []

# Bundle ripgrep if discoverable at build time.
rg_path = shutil.which('rg')
if rg_path:
    binaries.append((rg_path, '.'))
else:
    print("WARNING: ripgrep (rg) not found on PATH at build time; "
          "content search will return 503 at runtime.")

hiddenimports = collect_submodules('client') + [
    'core.binutil',
    'core.orm',
    'core.config',
    'core.crypto',
    'core.logging',
    'engine.ame',
    'engine.ume',
    'engine.keibatsu',
    'engine.facade',
    'net.commands',
    'net.connection',
    'net.sync',
    'net.search_limiter',
    'app.cli',
    'app.server',
]

a = Analysis(
    ['src/app/server.pyx'],
    pathex=[src_dir],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='bonnet',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
