# Developer Guide - SecureText Pro

## 🏗️ Project Structure

```
SecureText-Pro/
├── main.py                 # Main GUI application (Tkinter)
├── crypto_secure.py        # AES-256-GCM encryption module
├── cyber.py               # Simple fallback cipher (educational)
├── build_standalone.py    # PyInstaller build script
├── securetext_vault.db    # SQLite database (created at runtime)
└── README.md             # User documentation
```

## 🚀 Quick Start for Developers

### 1. Clone/Setup
```bash
# Install dependencies
pip install pycryptodome

# Run application
python main.py
```

### 2. Building Executable
```bash
# Install PyInstaller
pip install pyinstaller

# Build using script
python build_standalone.py

# Or manually
pyinstaller SecureText.spec
```

### 3. Testing
```bash
# Test text encryption
python -c "import crypto_secure; print(crypto_secure.encrypt('test', password='pass123'))"

# Test file encryption
python crypto_secure.py
```

## 📐 Architecture Overview

### Main Components

**1. GUI Layer (main.py)**
- Tabbed interface using Tkinter Notebook
- Tab 1: Text encryption/decryption
- Tab 2: File encryption/decryption
- User authentication and vault management

**2. Encryption Layer (crypto_secure.py)**
- AES-256-GCM implementation
- PBKDF2 key derivation
- File encryption/decryption functions
- Password hashing functions

**3. Database Layer (SQLite)**
- User accounts with secure password storage
- Encrypted message vault
- Settings (remember me, etc.)

### Data Flow

```
User Input → GUI → Crypto Module → Encrypted Output
                ↓
           Database (Vault)
```

## 🔐 Security Implementation

### Text Encryption Flow
```python
# Encryption
plaintext → PBKDF2(password, salt) → AES-256-GCM → base64 → ciphertext

# Components stored:
# - Salt (32 bytes, random)
# - IV/Nonce (16 bytes, random)
# - Ciphertext (variable length)
# - Auth Tag (16 bytes)
```

### File Encryption Flow
```python
# File format: [salt][nonce][tag][encrypted_data]
binary_data → PBKDF2(password, salt) → AES-256-GCM → .enc file
```

### Password Storage
```python
# User passwords never stored in plaintext
password → PBKDF2(480k iterations, random salt) → hash → database
```

## 🛠️ Key Classes and Functions

### EncryptionApp Class (main.py)

**Main Methods:**
- `__init__()` - Initialize GUI and database
- `build_text_tab()` - Create text encryption interface
- `build_file_tab()` - Create file encryption interface
- `do_action()` - Handle text encrypt/decrypt
- `encrypt_selected_file()` - Handle file encryption
- `decrypt_selected_file()` - Handle file decryption
- `save_to_vault()` - Save to user vault
- `load_from_vault()` - Load from vault

### SecureCrypto Class (crypto_secure.py)

**Static Methods:**
- `encrypt(plaintext, password)` - Encrypt text
- `decrypt(ciphertext, password)` - Decrypt text
- `derive_key(password, salt)` - PBKDF2 key derivation
- `hash_password_secure(password)` - Hash for storage
- `verify_password_secure(password, hash, salt)` - Verify password

**File Functions:**
- `encrypt_file(password, input_path, output_path)` - Encrypt file
- `decrypt_file(password, input_path, output_path)` - Decrypt file

## 💾 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,      -- PBKDF2 hash
    password_salt TEXT NOT NULL,      -- Base64 salt
    created_at TEXT NOT NULL
);
```

### Vault Table
```sql
CREATE TABLE vault (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    label TEXT NOT NULL,
    cipher_text TEXT NOT NULL,        -- Encrypted message
    password_hint TEXT,               -- Optional plaintext hint
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Settings Table
```sql
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Used for: remembered_user_id
```

## 🔧 Customization Guide

### Adding New Encryption Algorithms

1. **Add to crypto_secure.py:**
```python
@staticmethod
def encrypt_with_algorithm(plaintext, password, algorithm='AES-256'):
    # Implementation
    pass
```

2. **Update GUI to support selection:**
```python
self.algorithm_var = tk.StringVar(value='AES-256')
ttk.Radiobutton(frame, text='AES-256', variable=self.algorithm_var, value='AES-256')
ttk.Radiobutton(frame, text='ChaCha20', variable=self.algorithm_var, value='ChaCha20')
```

### Adding File Type Restrictions

```python
def select_file_encrypt(self):
    file_path = filedialog.askopenfilename(
        title="Select file",
        filetypes=[
            ("Images Only", "*.jpg *.png *.gif"),
            # Add/remove as needed
        ]
    )
```

### Custom Vault Fields

1. **Update database schema:**
```python
cursor.execute('''
    ALTER TABLE vault ADD COLUMN category TEXT;
''')
```

2. **Update save function:**
```python
cursor.execute('''
    INSERT INTO vault (user_id, label, cipher_text, category, ...)
    VALUES (?, ?, ?, ?, ...)
''', (user_id, label, cipher, category, ...))
```

## 🧪 Testing

### Unit Tests Example
```python
import unittest
from crypto_secure import SecureCrypto

class TestEncryption(unittest.TestCase):
    def test_encrypt_decrypt(self):
        plaintext = "Test message"
        password = "testpass123"
        
        cipher, _ = crypto.encrypt(plaintext, password=password)
        decrypted = crypto.decrypt(cipher, password=password)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_wrong_password(self):
        plaintext = "Test message"
        cipher, _ = crypto.encrypt(plaintext, password="correct")
        
        with self.assertRaises(ValueError):
            crypto.decrypt(cipher, password="wrong")
```

### Manual Testing Checklist
- [ ] Text encryption works
- [ ] Text decryption works
- [ ] Wrong password shows error
- [ ] File encryption preserves data
- [ ] File decryption restores original
- [ ] Vault save/load works
- [ ] User login/logout works
- [ ] Search functionality works
- [ ] Password hints display correctly

## 🐛 Debugging Tips

### Enable Console Output
```python
# In main.py, change console=False to console=True in spec file
console=True  # Shows debug output
```

### Add Logging
```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Use throughout code
logger.debug(f"Encrypting with password length: {len(password)}")
```

### Common Issues

**Issue:** "Crypto module not found"
```python
# Solution: Check import
try:
    from Crypto.Cipher import AES
    print("PyCryptodome installed correctly")
except ImportError:
    print("Install: pip install pycryptodome")
```

**Issue:** Database locked
```python
# Solution: Add timeout
conn = sqlite3.connect(self.db_file, timeout=10.0)
```

**Issue:** File permissions on .enc files
```python
# Solution: Check write permissions
if not os.access(output_dir, os.W_OK):
    raise PermissionError("Cannot write to directory")
```

## 📦 Distribution

### Windows Executable
```bash
# Build
python build_standalone.py

# Test
.\dist\SecureText-Pro.exe

# Sign (requires certificate)
signtool sign /f cert.pfx /p password /tr http://timestamp.digicert.com SecureText-Pro.exe
```

### macOS Application
```bash
# Build
pyinstaller SecureText.spec

# Create DMG
hdiutil create -volname "SecureText Pro" -srcfolder dist/SecureText-Pro.app -ov SecureText.dmg
```

### Linux Binary
```bash
# Build
pyinstaller SecureText.spec

# Make executable
chmod +x dist/SecureText-Pro

# Create .deb package (optional)
dpkg-deb --build securetext-pro
```

## 🔒 Security Considerations for Developers

### DO:
- ✅ Use secure random generation (`secrets` module)
- ✅ Use constant-time comparison for passwords (`hmac.compare_digest`)
- ✅ Clear sensitive data from memory when possible
- ✅ Validate all user inputs
- ✅ Use parameterized SQL queries

### DON'T:
- ❌ Store passwords in plaintext (even temporarily)
- ❌ Log sensitive data (passwords, keys, plaintext)
- ❌ Use weak random generators (`random.random()`)
- ❌ Hardcode secrets in source code
- ❌ Use string concatenation for SQL

### Code Review Checklist
- [ ] No hardcoded secrets
- [ ] All passwords are hashed
- [ ] SQL injection prevention (parameterized queries)
- [ ] Proper error handling (no sensitive info in errors)
- [ ] Input validation on all user inputs
- [ ] Secure random generation for crypto operations
- [ ] Constant-time comparisons for secrets

## 📚 Dependencies

### Required
- **Python 3.7+**
- **pycryptodome** - AES encryption
- **tkinter** - GUI (usually included with Python)
- **sqlite3** - Database (included with Python)

### Optional (Development)
- **pyinstaller** - For building executables
- **pytest** - For testing
- **black** - Code formatting
- **pylint** - Code linting

## 🤝 Contributing

### Code Style
```python
# Use Black formatter
black main.py crypto_secure.py

# Follow PEP 8
# Use type hints where possible
def encrypt(plaintext: str, password: str) -> Tuple[str, str]:
    pass
```

### Pull Request Process
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Testing Requirements
- All new features must include tests
- Maintain or improve code coverage
- Update documentation

## 📞 Support

### For Developers
- Check issues on GitHub
- Review closed PRs for solutions
- Read the security guide thoroughly

### Reporting Security Issues
**DO NOT** open public issues for security vulnerabilities.
Contact maintainers privately.

## 📖 Further Reading

- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/)
- [Python Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)
- [SQLite Documentation](https://www.sqlite.org/docs.html)

---

*Happy coding! 🚀*