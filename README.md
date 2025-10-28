# What SecureText does.
## Secure your text
This enables encryption and decryption of any messages that the user wishes to keep secret and only known by the parties involved
## Secure your sensitive data
This enables encryption of your sensitive information like bank accounts, ATM credentials and others. Then even if you save in cloud, save the encrypted data
## Ensuring Privacy
Since the information can only be decrypted offline, then it remains private between only the parties concerned.
## Save your data
The app has a built in database that can save user's information and can be accessd on validation

# HOW TO USE
The user can easily use it for encrypting any text information they are sending out of there devices and then decrypt the ones that are sent unto them.
Users can create their accounts locally to save important data they feel like saving


# SecureText Pro - Encryption Tool

**Version 1.0** | Production-Ready AES-256-GCM Encryption

---

## 🎯 Overview

SecureText Pro is a user-friendly encryption tool that allows you to:
- **Encrypt & decrypt text messages** with AES-256-GCM encryption
- **Encrypt & decrypt files** (images, videos, documents, etc.)
- **Save encrypted messages** to your personal vault
- **Manage multiple user accounts** with secure password hashing

---

## ✨ Features

### 🔐 Text Encryption
- Industry-standard AES-256-GCM encryption
- PBKDF2 key derivation with 600,000 iterations
- Password-based encryption
- Copy encrypted text to clipboard
- Save encrypted messages to vault

### 📁 File Encryption
- Encrypt any file type (images, videos, PDFs, documents, etc.)
- Files encrypted with .enc extension
- Original files can be fully restored
- Password protection with strong encryption

### 💾 Personal Vault
- Save encrypted messages with labels
- Add password hints (optional)
- Search functionality
- Quick load and decrypt

### 👤 User Accounts
- Multi-user support
- Secure password hashing (PBKDF2)
- Remember me functionality
- Personal vault per user

---

## 🚀 Getting Started

### Installation

#### Option 1: Standalone Executable (Recommended)
1. Download `SecureText-Pro.exe` (Windows) or `SecureText-Pro` (Mac/Linux)
2. Double-click to run - no installation needed!
3. That's it! No Python or dependencies required.

#### Option 2: Run from Source
```bash
# Install dependencies
pip install pycryptodome

# Run the application
python main.py
```

---

## 📖 How to Use

### Text Encryption

#### Encrypting Text:
1. Go to the **📝 Text Encryption** tab
2. Select **🔒 Encrypt Text** mode
3. Enter your text in the input field
4. Enter a strong password
5. Click **🔐 Encrypt**
6. Copy the encrypted output or save to vault

#### Decrypting Text:
1. Select **🔓 Decrypt Text** mode
2. Paste encrypted text in the input field
3. Enter the password used for encryption
4. Click **🔓 Decrypt**
5. View your original text

### File Encryption

#### Encrypting Files:
1. Go to the **📁 File Encryption** tab
2. Click **📁 Select File to Encrypt**
3. Choose any file (image, video, document, etc.)
4. Enter a strong password
5. Click **🔐 Encrypt File**
6. Your file will be saved with `.enc` extension

#### Decrypting Files:
1. Click **🔓 Select .enc File to Decrypt**
2. Choose the encrypted `.enc` file
3. Enter the password used for encryption
4. Click **🔓 Decrypt File**
5. Original file will be restored

### Using the Vault

1. Click **🔐 Login** to create an account or log in
2. Encrypt some text
3. Click **💾 Save to Vault**
4. Add a label and optional password hint
5. Access saved messages anytime from the vault list
6. Double-click or click **📂 Load** to retrieve

---

## 🔒 Security Features

### Encryption Specifications

**Text & File Encryption:**
- **Algorithm**: AES-256-GCM (Authenticated Encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000 (OWASP 2023 recommendation)
- **Salt**: 256-bit random salt (unique per encryption)
- **Authentication**: 128-bit authentication tag

**Password Storage:**
- **Hashing**: PBKDF2-HMAC-SHA256
- **Iterations**: 480,000 for passwords
- **Salt**: Unique random salt per user

### Security Best Practices

✅ **DO:**
- Use strong, unique passwords (8+ characters)
- Store encrypted files safely
- Keep backups of important files
- Remember your passwords!

❌ **DON'T:**
- Use weak passwords (e.g., "password123")
- Share passwords via insecure channels
- Lose your password (unrecoverable!)
- Encrypt files without backups

---

## ⚠️ Important Warnings

### Password Recovery
**🚨 CRITICAL:** If you forget your password, **your data CANNOT be recovered**. There is no "forgot password" option or backdoor. This is by design for security.

**Solutions:**
- Write down important passwords in a secure location
- Use a password manager
- Add password hints when saving to vault

### File Encryption
- Always keep a backup of original files before encrypting
- Test decryption immediately after encryption
- Encrypted files with `.enc` extension are the ONLY way to recover originals
- Don't delete `.enc` files until you've verified decryption works

### Database Security
- Your vault database (`securetext_vault.db`) contains encrypted messages
- Keep this file safe and backed up
- If deleted, all vault contents are lost
- Password hints are stored **unencrypted** - don't put sensitive info in hints

---

## 🛠️ Building from Source

### Prerequisites
```bash
# Install Python 3.7 or higher
# Then install dependencies:
pip install pycryptodome
pip install pyinstaller  # Only for building executable
```

### Build Standalone Executable
```bash
# Run the build script
python build_standalone.py

# Your executable will be in the dist/ folder
```

### Manual Build
```bash
# Using PyInstaller
pyinstaller --onefile --windowed --name "SecureText-Pro" \
    --add-data "crypto_secure.py:." \
    --hidden-import "Crypto.Cipher.AES" \
    --hidden-import "Crypto.Random" \
    main.py
```

---

## 📊 Technical Details

### File Structure
```
SecureText-Pro/
├── main.py                    # Main application GUI
├── crypto_secure.py           # AES-256 encryption module
├── cyber.py                   # Fallback simple cipher
├── build_standalone.py        # Build script
├── securetext_vault.db        # User database (created on first run)
├── README.md                  # This file
└── dist/                      # Built executable location
    └── SecureText-Pro.exe
```

### Database Schema

**Users Table:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    password_salt TEXT,
    created_at TEXT
);
```

**Vault Table:**
```sql
CREATE TABLE vault (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    label TEXT,
    cipher_text TEXT,
    password_hint TEXT,
    created_at TEXT,
    updated_at TEXT
);
```

### Encrypted File Format
```
[16 bytes: Salt]
[16 bytes: IV/Nonce]
[16 bytes: Authentication Tag]
[Remaining: Encrypted Data]
```

---

## 🐛 Troubleshooting

### "PyCryptodome not found" Error
**Problem:** File encryption requires PyCryptodome library

**Solution:**
```bash
pip install pycryptodome
```

### "Decryption Failed" Error
**Possible Causes:**
1. Wrong password
2. File is corrupted
3. File was encrypted with different software

**Solutions:**
- Double-check your password
- Try the password hint if you added one
- Ensure the `.enc` file hasn't been modified

### Executable Won't Run (Windows)
**Problem:** Windows SmartScreen warning

**Solution:**
- Click "More info" → "Run anyway"
- Or: Have the developer code-sign the executable

### Database Locked Error
**Problem:** Another instance is running

**Solution:**
- Close all SecureText windows
- Check Task Manager for running processes
- Restart the application

---

## 💡 Tips & Tricks

### Password Management
- Use a password manager (LastPass, 1Password, Bitwarden)
- Create strong passwords: mix of uppercase, lowercase, numbers, symbols
- Use different passwords for different encrypted items
- Add meaningful password hints in the vault

### File Organization
- Keep encrypted files in a dedicated folder
- Use descriptive filenames: `photo_backup_2024.jpg.enc`
- Document which password was used (without storing the actual password)
- Test decryption immediately after encryption

### Vault Usage
- Use descriptive labels: "Bank Info - Dec 2024"
- Add password hints that only you understand
- Regularly backup your vault database
- Export important encrypted texts separately

### Backup Strategy
1. **Regular backups** of `securetext_vault.db`
2. **Store encrypted files** in cloud storage (they're already encrypted!)
3. **Keep password lists** in a secure physical location
4. **Test recovery** periodically

---

## 🔄 Version History

### Version 1.0 (Current)
- ✨ Initial release
- 🔐 AES-256-GCM text encryption
- 📁 File encryption for any file type
- 💾 Personal vault with user accounts
- 🔍 Search functionality
- 👤 Multi-user support
- 🎨 Modern tabbed interface

---

## 📞 Support & Feedback

### Reporting Issues
If you encounter bugs or issues:
1. Note the exact error message
2. Document steps to reproduce
3. Check if you're using the latest version
4. Report to the developer

### Feature Requests
We welcome suggestions for improvements!

---

## ⚖️ License & Disclaimer

### Educational & Personal Use
This software is provided for educational and personal use.

### Disclaimer
- **NO WARRANTY**: This software is provided "as is"
- **DATA LOSS**: Always keep backups of important data
- **SECURITY**: While using industry-standard encryption, no system is 100% secure
- **LEGAL**: User is responsible for compliance with local laws
- **PASSWORDS**: Lost passwords cannot be recovered

### Security Notice
This tool uses:
- **AES-256-GCM**: NIST-approved encryption algorithm
- **PBKDF2**: Industry-standard key derivation
- **Proper salting**: Unique salt per encryption

However:
- It's not audited by professional security firms
- Use at your own risk for sensitive data
- For critical data, consider professionally audited tools

---

## 🙏 Credits

Built with:
- **Python** - Programming language
- **Tkinter** - GUI framework
- **PyCryptodome** - Cryptography library
- **SQLite** - Database engine

Encryption standards:
- **NIST** - AES standard
- **OWASP** - Security recommendations
- **RFC 2898** - PBKDF2 specification

---

## 📚 Additional Resources

### Learn More About Encryption
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [OWASP Cryptography Cheat Sheet](https://cheatsheetseries.owasp.org/)
- [Understanding AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

### Password Security
- [How to Create Strong Passwords](https://www.cisa.gov/secure-our-world/use-strong-passwords)
- [Password Managers Comparison](https://www.privacytools.io/password-managers)

### File Security Best Practices
- [Data Backup Strategy Guide](https://www.backblaze.com/blog/the-3-2-1-backup-strategy/)
- [Encryption Best Practices](https://www.cisecurity.org/)

---

## 🎯 Quick Reference Card

### Common Tasks

| Task | Steps |
|------|-------|
| **Encrypt Text** | Text tab → Enter text → Enter password → Encrypt |
| **Decrypt Text** | Text tab → Switch to Decrypt → Paste text → Enter password → Decrypt |
| **Encrypt File** | File tab → Select file → Enter password → Encrypt File |
| **Decrypt File** | File tab → Select .enc file → Enter password → Decrypt File |
| **Save to Vault** | Login → Encrypt text → Save to Vault → Add label |
| **Load from Vault** | Login → Select item → Load → Enter password → Decrypt |

### Keyboard Shortcuts
- **Ctrl+A**: Select all text in input field
- **Ctrl+C**: Copy selected text
- **Ctrl+V**: Paste text
- **Tab**: Navigate between fields

---

## 🌟 Final Notes

Thank you for using SecureText Pro! 

**Remember:**
- 🔐 Strong passwords are your first line of defense
- 💾 Always keep backups
- 🧠 Don't forget your passwords!
- ✅ Test decryption immediately

**Stay secure!** 🛡️

---

*SecureText Pro v1.0 - Secure. Simple. Reliable.*