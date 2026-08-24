# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Bonnet (pure Python).

Bundles the pure-Python server modules and, when available, the ripgrep (`rg`)
binary so that `bonnet.core.binutil.resolve_rg` can find it under ``sys._MEIPASS`` at
runtime. If `rg` is not present on PATH at build time the build still succeeds
-- the server returns 503 for content search in that case.
"""

import os
import shutil
from PyInstaller.utils.hooks import collect_submodules

src_dir = 'src'

datas = []
binaries = []

# Bundle ripgrep if discoverable at build time.
# BONNET_RG_PATH env var overrides PATH lookup for the binary to bundle.
rg_path = os.environ.get('BONNET_RG_PATH') or shutil.which('rg')
if rg_path:
    binaries.append((rg_path, '.'))
else:
    print("WARNING: ripgrep (rg) not found (set BONNET_RG_PATH or add to PATH) "
          "at build time; content search will return 503 at runtime.")

hiddenimports = collect_submodules('bonnet.client') + [
    'bonnet.core.acl',
    'bonnet.core.binutil',
    'bonnet.core.board_projection',
    'bonnet.core.bodies',
    'bonnet.core.config',
    'bonnet.core.crypto',
    'bonnet.core.dispatcher',
    'bonnet.core.firehose',
    'bonnet.core.global_projections',
    'bonnet.core.kind_validator',
    'bonnet.core.logging',
    'bonnet.core.record',
    'bonnet.core.search',
    'bonnet.core.trust',
    'bonnet.net.firehose_commands',
    'bonnet.net.firehose_http_server',
    'bonnet.net.firehose_sync',
    'bonnet.net.http_auth',
    'bonnet.net.rate_limiter',
    'bonnet.net.replay',
    'bonnet.app.cli',
    'bonnet.app.server',
]

a = Analysis(
    ['src/bonnet/app/main.py'],
    pathex=[src_dir],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data)

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
