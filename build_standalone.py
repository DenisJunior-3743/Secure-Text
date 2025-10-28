"""
Build Script for SecureText Pro
Creates a standalone executable with all dependencies bundled
"""

import os
import sys
import subprocess
import shutil

def check_dependencies():
    """Check if required packages are installed"""
    print("Checking dependencies...")
    
    required = {
        'pyinstaller': 'pyinstaller',
        'pycryptodome': 'Crypto'
    }
    
    missing = []
    for package, import_name in required.items():
        try:
            __import__(import_name)
            print(f"✓ {package} is installed")
        except ImportError:
            print(f"✗ {package} is NOT installed")
            missing.append(package)
    
    if missing:
        print(f"\n⚠️ Missing packages: {', '.join(missing)}")
        print("\nInstall them with:")
        print(f"pip install {' '.join(missing)}")
        return False
    
    return True

def create_spec_file():
    """Create PyInstaller spec file for better control"""
    spec_content = """# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('crypto_secure.py', '.'),
        ('cyber.py', '.'),
    ],
    hiddenimports=[
        'Crypto.Cipher.AES',
        'Crypto.Random',
        'Crypto.Util.Padding',
        'Crypto.Hash.HMAC',
        'Crypto.Hash.SHA256',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
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
    name='SecureText-Pro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window (GUI only)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
    
    with open('SecureText.spec', 'w') as f:
        f.write(spec_content)
    
    print("✓ Created PyInstaller spec file")

def build_executable():
    """Build the executable using PyInstaller"""
    print("\n" + "="*60)
    print("Building SecureText Pro Standalone Executable")
    print("="*60 + "\n")
    
    # Check if files exist
    required_files = ['main.py', 'crypto_secure.py', 'cyber.py']
    for file in required_files:
        if not os.path.exists(file):
            print(f"✗ Error: {file} not found!")
            return False
    
    print("✓ All source files found")
    
    # Clean previous builds
    print("\nCleaning previous builds...")
    dirs_to_clean = ['build', 'dist', '__pycache__']
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"  Removed {dir_name}/")
    
    # Remove old spec file
    if os.path.exists('SecureText.spec'):
        os.remove('SecureText.spec')
    
    print("\n" + "-"*60)
    print("Creating spec file...")
    print("-"*60)
    create_spec_file()
    
    print("\n" + "-"*60)
    print("Building executable (this may take a few minutes)...")
    print("-"*60 + "\n")
    
    try:
        # Build using the spec file
        subprocess.run(['pyinstaller', 'SecureText.spec', '--clean'], check=True)
        
        print("\n" + "="*60)
        print("✓ BUILD SUCCESSFUL!")
        print("="*60)
        print(f"\nExecutable location: dist/SecureText-Pro")
        if sys.platform == 'win32':
            print("(Windows: dist/SecureText-Pro.exe)")
        
        # Show file size
        if sys.platform == 'win32':
            exe_path = 'dist/SecureText-Pro.exe'
        else:
            exe_path = 'dist/SecureText-Pro'
        
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print(f"File size: {size_mb:.2f} MB")
        
        print("\n" + "-"*60)
        print("NEXT STEPS:")
        print("-"*60)
        print("1. Test the executable on your machine")
        print("2. Test on a clean machine without Python installed")
        print("3. Consider code signing (Windows) to avoid security warnings")
        print("4. Create an installer with Inno Setup (optional)")
        print("\nFor distribution:")
        print("• Compress the executable for easier sharing")
        print("• Include README with instructions")
        print("• Warn users about remembering passwords!")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Build failed: {e}")
        return False
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        return False

def main():
    print("\n" + "="*60)
    print("SecureText Pro - Build Script")
    print("="*60 + "\n")
    
    # Check dependencies
    if not check_dependencies():
        print("\n⚠️ Please install missing dependencies first.")
        sys.exit(1)
    
    # Build
    success = build_executable()
    
    if success:
        print("\n✓ All done! Your executable is ready.")
    else:
        print("\n✗ Build failed. Please check the errors above.")
        sys.exit(1)

if __name__ == '__main__':
    main()