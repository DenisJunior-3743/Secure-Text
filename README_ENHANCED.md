# 🔐 SecureText Pro - Complete Encryption Suite

**Version 2.0** - Enhanced Modular Architecture with Audio Support

---

## 🌟 What's New in Version 2.0

### ✨ Major Enhancements

1. **📝 Text Encryption** - Secure AES-256 encryption for messages
2. **🖼️ Image/Video Encryption** - Encrypt any file with live preview
3. **🎵 Audio Encryption** - NEW! Encrypt audio files with built-in player
4. **💾 Enhanced Vault** - Better organized vault with search and export
5. **🎨 Consistent UI** - Beautiful, modern interface with vertical scrollbars
6. **🔧 Modular Architecture** - Each module is independent and failure-isolated

### 🎯 Key Features

- **Modular Design**: Each encryption type has its own isolated module
- **Consistent Theme**: Beautiful color scheme across all tabs
- **Live Previews**: View images and play audio directly in the app
- **Scrollable Interface**: Smooth vertical scrolling in all tabs
- **Error Isolation**: Failure in one module doesn't affect others
- **Enhanced Security**: AES-256-GCM with PBKDF2 key derivation

---

## 📦 Installation

### Quick Start

```bash
# Install required dependencies
pip install pycryptodome pillow pygame

# Run the application
python main_enhanced.py
```

### Dependencies

**Required:**
- `pycryptodome` - For AES-256 encryption
- `pillow` - For image preview support
- `tkinter` - GUI framework (usually pre-installed with Python)

**Optional:**
- `pygame` - For audio playback (audio encryption works without it)

### Installation Commands

```bash
# Install all dependencies
pip install pycryptodome pillow pygame

# Or install individually
pip install pycryptodome  # Required for all encryption
pip install pillow        # Required for image preview
pip install pygame        # Optional, for audio playback
```

---

## 🗂️ Project Structure

```
SecureText-Pro-Enhanced/
├── main_enhanced.py           # Main application (enhanced GUI)
├── crypto_secure.py            # Text & file encryption module
├── crypto_audio.py             # Audio encryption module (NEW)
├── cyber.py                    # Fallback cipher (educational)
├── build_standalone.py         # Build script
├── securetext_vault.db         # User database (auto-created)
├── README_ENHANCED.md          # This file
└── DEVELOPER_GUIDE.md          # Developer documentation
```

### Module Architecture

```
┌─────────────────────────────────────────────┐
│         Main Application (GUI)              │
│         (main_enhanced.py)                  │
└─────────────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
┌───────▼──────┐ ┌──▼─────────┐ ┌─────▼───────┐
│ Text Module  │ │File Module │ │Audio Module │
│crypto_secure │ │crypto_secure│ │crypto_audio │
└──────────────┘ └─────────────┘ └─────────────┘
```

**Key Benefits:**
- ✅ Independent modules
- ✅ Failure isolation
- ✅ Easy to extend
- ✅ Maintainable code

---

## 📖 How to Use

### 📝 Text Encryption

1. **Go to Text Tab**
2. **Select Mode**: Choose Encrypt or Decrypt
3. **Enter Text**: Type or paste your message
4. **Enter Password**: Use a strong password
5. **Click Encrypt/Decrypt**
6. **Copy or Save**: Copy output or save to vault

**Tips:**
- Use strong passwords (8+ characters)
- Save to vault for easy access later
- Use password hints (stored unencrypted)

### 🖼️ Image/Video Encryption

1. **Go to Images/Video Tab**
2. **Select File**: Click "Select File to Encrypt"
3. **Preview**: See your image in the preview area
4. **Enter Password**: Choose a secure password
5. **Encrypt**: File saved with `.enc` extension
6. **Decrypt**: Select `.enc` file and decrypt to restore

**Supported Formats:**
- **Images**: JPG, PNG, GIF, BMP, WEBP
- **Videos**: MP4, AVI, MKV, MOV, WMV
- **Documents**: PDF, DOC, DOCX, TXT, XLSX

**Features:**
- ✅ Live image preview
- ✅ File size display
- ✅ Detailed status log
- ✅ Automatic extension handling

### 🎵 Audio Encryption

1. **Go to Audio Tab**
2. **Select Audio**: Click "Select Audio to Encrypt"
3. **Enter Password**: Choose a secure password
4. **Encrypt**: File saved with `.aenc` extension
5. **Decrypt**: Select `.aenc` file and decrypt
6. **Play**: Use built-in player to listen

**Supported Formats:**
- MP3, WAV, OGG, FLAC, M4A, AAC

**Player Controls:**
- ▶️ **Play**: Start playback
- ⏸️ **Pause**: Pause/Resume
- ⏹️ **Stop**: Stop playback
- 🔊 **Volume**: Adjust volume (0-100%)

**Note:** Audio playback requires `pygame`. Encryption works without it.

### 💾 Vault Management

1. **Login**: Create account or login
2. **Save Messages**: Encrypt text, then click "Save to Vault"
3. **Add Labels**: Give meaningful names
4. **Password Hints**: Add optional hints (unencrypted)
5. **Search**: Find messages quickly
6. **Load**: Double-click to load and decrypt
7. **Export**: Export entire vault to text file

**Vault Features:**
- ✅ Search functionality
- ✅ Sort by date
- ✅ Password hints
- ✅ Export to file
- ✅ Multi-user support

---

## 🎨 User Interface

### Theme & Design

**Consistent Colors:**
- Background: `#f5f5f5` (Light gray)
- Primary Accent: `#2196F3` (Blue)
- Success: `#2e7d32` (Green)
- Warning: `#f57c00` (Orange)
- Error: `#d32f2f` (Red)

**UI Features:**
- ✅ Vertical scrollbars in all tabs
- ✅ Consistent padding and spacing
- ✅ Modern, clean design
- ✅ Responsive layout
- ✅ Smooth scrolling

### Navigation

**Tabs:**
1. 📝 **Text** - Message encryption
2. 🖼️ **Images/Video** - File encryption with preview
3. 🎵 **Audio** - Audio encryption with player
4. 💾 **My Vault** - Saved messages

**Top Bar:**
- Security status indicator
- User account display
- Login/Logout buttons

**Status Bar:**
- Real-time operation status
- Success/error messages

---

## 🔒 Security Features

### Encryption Standards

**Text Encryption:**
- Algorithm: AES-256-GCM
- Key Derivation: PBKDF2-HMAC-SHA256
- Iterations: 600,000
- Salt: 256-bit random
- Authentication: 128-bit tag

**File Encryption:**
- Same as text encryption
- File format: `[salt][nonce][tag][ciphertext]`
- Extension: `.enc` for files, `.aenc` for audio

**Password Storage:**
- Algorithm: PBKDF2-HMAC-SHA256
- Iterations: 480,000
- Salt: Unique per user
- Never stored in plaintext

### Best Practices

✅ **DO:**
- Use strong, unique passwords
- Keep backups of encrypted files
- Test decryption immediately
- Remember your passwords
- Use password manager

❌ **DON'T:**
- Use weak passwords
- Share passwords insecurely
- Delete `.enc` files without backup
- Forget your passwords (unrecoverable!)
- Store password hints with sensitive info

---

## 🔧 Troubleshooting

### Common Issues

#### "Module not found" Errors

**Problem:** Missing dependencies

**Solution:**
```bash
pip install pycryptodome pillow pygame
```

#### Audio Playback Not Working

**Problem:** Pygame not installed

**Solution:**
```bash
pip install pygame
```

Note: Audio encryption works without pygame; only playback requires it.

#### Image Preview Not Showing

**Problem:** PIL/Pillow not installed

**Solution:**
```bash
pip install pillow
```

#### "Decryption Failed" Error

**Possible Causes:**
1. Wrong password
2. Corrupted file
3. File encrypted with different software

**Solutions:**
- Double-check password
- Try password hint
- Ensure file wasn't modified

#### Database Locked

**Problem:** Multiple instances running

**Solution:**
- Close all SecureText windows
- Check Task Manager
- Restart application

---

## 🚀 Building Standalone Executable

### Using Build Script

```bash
# Run the build script
python build_standalone.py

# Your executable will be in dist/ folder
```

### Manual Build

```bash
# Install PyInstaller
pip install pyinstaller

# Build
pyinstaller --onefile --windowed \
    --name "SecureText-Pro-Enhanced" \
    --add-data "crypto_secure.py:." \
    --add-data "crypto_audio.py:." \
    --hidden-import "Crypto.Cipher.AES" \
    --hidden-import "PIL" \
    --hidden-import "pygame" \
    main_enhanced.py
```

---

## 🎯 Advanced Features

### Module Independence

Each encryption module is independent:

```python
# Text module
import crypto_secure

# Audio module  
import crypto_audio

# Each module can fail independently
# without affecting others
```

**Benefits:**
- No cascading failures
- Easy debugging
- Simple to extend
- Maintainable code

### Error Handling

Each module has comprehensive error handling:

```python
try:
    result = encrypt_audio(password, file)
except Exception as e:
    # Error logged, user notified
    # Other modules continue working
    handle_error(e)
```

### Extending the Application

**Add New Encryption Type:**

1. Create new module (e.g., `crypto_documents.py`)
2. Implement `encrypt_document()` and `decrypt_document()`
3. Add new tab in `build_document_tab()`
4. Add UI controls and preview
5. Done! Module is isolated and independent

---

## 📊 Performance & Limits

### File Size Limits

- **Text**: Virtually unlimited
- **Files**: Limited by available RAM
- **Audio**: Recommended < 100MB for smooth playback

### Performance

- **Text Encryption**: Near-instant for typical messages
- **File Encryption**: ~1-2 MB/second
- **Audio Decryption**: Real-time for playback

### Memory Usage

- Base application: ~50-100 MB
- + Image preview: Up to image size
- + Audio player: Up to audio file size

---

## 🤝 Contributing

### Code Style

```python
# Use consistent naming
def encrypt_audio(password, input_path, output_path=None):
    """Clear docstrings"""
    pass

# Type hints where appropriate
def format_size(size_bytes: int) -> str:
    """Format file size"""
    pass
```

### Testing

Test each module independently:

```bash
# Test text encryption
python -c "import crypto_secure; print('OK')"

# Test audio encryption
python -c "import crypto_audio; print('OK')"

# Test GUI
python main_enhanced.py
```

---

## 📝 Version History

### Version 2.0 (Current)
- ✨ Added audio encryption module
- ✨ Added audio player with controls
- ✨ Modular architecture
- ✨ Consistent UI theme
- ✨ Vertical scrollbars everywhere
- ✨ Enhanced vault with export
- ✨ Live image preview
- 🐛 Fixed numerous bugs
- 📚 Improved documentation

### Version 1.0
- Initial release
- Text encryption
- File encryption
- Basic vault
- User accounts

---

## 🙏 Acknowledgments

**Built With:**
- Python - Programming language
- Tkinter - GUI framework
- PyCryptodome - Cryptography
- Pillow - Image processing
- Pygame - Audio playback

**Standards:**
- NIST AES-256
- OWASP PBKDF2 recommendations
- Modern encryption best practices

---

## 📄 License & Disclaimer

### Educational & Personal Use

This software is for educational and personal use.

### Disclaimer

- ⚠️ NO WARRANTY provided
- ⚠️ Always keep backups
- ⚠️ Lost passwords are unrecoverable
- ⚠️ Use at your own risk
- ⚠️ Follow local laws

### Security Notice

While using industry-standard encryption:
- Not professionally audited
- Not certified for commercial use
- For sensitive data, use professionally audited tools

---

## 📞 Support

### Getting Help

1. Check this README
2. Review DEVELOPER_GUIDE.md
3. Check error messages
4. Search for similar issues

### Reporting Bugs

When reporting bugs, include:
- Error message (exact text)
- Steps to reproduce
- Python version
- Operating system
- Dependencies installed

---

## 🎓 Learning Resources

### Encryption Basics
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [OWASP Cryptography](https://cheatsheetseries.owasp.org/)
- [Understanding AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

### Python GUI
- [Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)
- [Tkinter Tutorial](https://realpython.com/python-gui-tkinter/)

### Audio Processing
- [Pygame Mixer](https://www.pygame.org/docs/ref/mixer.html)
- [Audio Formats Guide](https://en.wikipedia.org/wiki/Audio_file_format)

---

## 🎯 Quick Reference

### Keyboard Shortcuts

- **Ctrl+C**: Copy
- **Ctrl+V**: Paste
- **Ctrl+A**: Select all
- **Tab**: Navigate fields
- **Enter**: Submit in dialogs

### File Extensions

- `.enc` - Encrypted file (images/video/documents)
- `.aenc` - Encrypted audio file
- `.db` - SQLite database (vault)

### Password Requirements

- **Minimum Length**: 6 characters (8+ recommended)
- **Recommendations**: 
  - Mix uppercase & lowercase
  - Include numbers
  - Include symbols
  - Avoid common words

---

## 💡 Pro Tips

1. **Organize Your Vault**: Use clear, descriptive labels
2. **Password Hints**: Make them meaningful but not obvious
3. **Test Decryption**: Always test immediately after encryption
4. **Keep Backups**: Don't delete originals until you verify
5. **Use Search**: Quickly find vault items with search
6. **Export Regularly**: Export vault as backup
7. **Strong Passwords**: Use a password manager
8. **Preview Feature**: Use image preview to verify files
9. **Audio Player**: Test audio immediately after decryption
10. **Module Independence**: If one feature fails, others still work

---

## 🔮 Future Enhancements

Potential features for future versions:

- 📹 Video playback in preview
- 🗂️ Batch encryption
- 📱 Mobile companion app
- ☁️ Cloud sync (encrypted)
- 🔑 Key file support
- 📊 Usage statistics
- 🎨 Theme customization
- 🌐 Multi-language support

---

**SecureText Pro v2.0 - Secure. Modular. Beautiful.**

*Your privacy, your control.* 🔐