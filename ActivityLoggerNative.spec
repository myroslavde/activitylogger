# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['interleaved_logger.py'],
    pathex=[],
    binaries=[],
    datas=[('docs/V2_RECOVERY.md', 'docs')],
    hiddenimports=['analysis_log', 'browser_url', 'window_titles', 'config', 'scroll_coalesce', 'markdown_format', 'review_center', 'Quartz'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ActivityLoggerNative',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
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
    upx=False,
    upx_exclude=[],
    name='ActivityLoggerNative',
)
app = BUNDLE(
    coll,
    name='ActivityLoggerNative.app',
    icon='assets/ActivityLogger.icns',
    bundle_identifier='com.mk.activitylogger.native',
    info_plist={
        'CFBundleShortVersionString': '4.6.1',
        'CFBundleVersion': '4.6.1',
        'NSHighResolutionCapable': True,
        'LSBackgroundOnly': False,
        'LSUIElement': True,
        'NSAppleEventsUsageDescription': (
            'ActivityLogger reads the active browser tab address when browser URL capture is enabled.'
        ),
    },
)
