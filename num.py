import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import sqlite3
import os
from datetime import datetime
import sys



# Import the secure crypto module
try:
    import crypto_secure as crypto
    CRYPTO_MODE = "SECURE"
except ImportError:
    import cyber as crypto  # Fallback to simple cipher
    CRYPTO_MODE = "SIMPLE"

def resource_path(rel_path):
    """Return absolute path to resource, working for dev and for PyInstaller executable."""
    if getattr(sys, 'frozen', False):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, rel_path)

DB_FILE = resource_path('securetext_vault.db')


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        title = 'SecureText - Encryption Tool'
        if CRYPTO_MODE == "SECURE":
            title += ' [AES-256]'
        else:
            title += ' [Basic Mode]'
        self.root.title(title)
        self.root.geometry('900x850')
        self.root.minsize(720, 600)
        self.root.resizable(True, True)
        
        self.db_file = DB_FILE
        self.init_database()
        
        # Current user state
        self.current_user_id = None
        self.current_username = None
        
        self.check_remembered_login()
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        bg_color = '#f0f0f0'
        self.root.configure(bg=bg_color)
        
        # Create main scrollable canvas
        canvas = tk.Canvas(root, bg=bg_color, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(root, orient='vertical', command=canvas.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        canvas.configure(yscrollcommand=scrollbar.set)
        
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        
        main_frame = ttk.Frame(canvas, padding="20")
        canvas_window = canvas.create_window((0, 0), window=main_frame, anchor='nw')
        
        main_frame.columnconfigure(0, weight=1)
        
        def configure_scroll_region(event):
            canvas.configure(scrollregion=canvas.bbox('all'))
        
        def configure_canvas_width(event):
            canvas_width = event.width
            canvas.itemconfig(canvas_window, width=canvas_width)
        
        main_frame.bind('<Configure>', configure_scroll_region)
        canvas.bind('<Configure>', configure_canvas_width)
        
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def bind_mousewheel(event):
            canvas.bind_all("<MouseWheel>", on_mousewheel)
            canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
            canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
        
        def unbind_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")
        
        canvas.bind('<Enter>', bind_mousewheel)
        canvas.bind('<Leave>', unbind_mousewheel)
        
        # Header with security indicator
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        header_frame.columnconfigure(0, weight=1)
        
        title_label = ttk.Label(header_frame, text='SecureText Encryption Tool', 
                                font=('Segoe UI', 18, 'bold'))
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        # Security mode indicator
        security_frame = ttk.Frame(main_frame)
        security_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        if CRYPTO_MODE == "SECURE":
            security_color = '#2e7d32'
            security_text = '🔒 Secure Mode: AES-256-GCM Encryption (Production Ready)'
        else:
            security_color = '#f57c00'
            security_text = '⚠️ Basic Mode: Simple Cipher (Educational Use Only)'
        
        security_label = ttk.Label(security_frame, text=security_text,
                                  font=('Segoe UI', 9, 'bold'),
                                  foreground=security_color)
        security_label.pack()
        
        # User status frame
        user_frame = ttk.Frame(header_frame)
        user_frame.grid(row=0, column=1, sticky=tk.E)
        
        self.user_status_label = ttk.Label(user_frame, text='Guest Mode', 
                                           font=('Segoe UI', 10))
        self.user_status_label.grid(row=0, column=0, padx=(0, 10))
        
        self.login_btn = ttk.Button(user_frame, text='🔐 Login', 
                                    command=self.show_login_dialog, width=12)
        self.login_btn.grid(row=0, column=1, padx=2)
        
        self.logout_btn = ttk.Button(user_frame, text='🚪 Logout', 
                                     command=self.logout, width=12)
        self.logout_btn.grid(row=0, column=2, padx=2)
        
        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text='Mode', padding="10")
        mode_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.mode_var = tk.StringVar(value='encrypt')
        encrypt_radio = ttk.Radiobutton(mode_frame, text='🔒 Encrypt', 
                                       variable=self.mode_var, value='encrypt',
                                       command=self.update_ui_for_mode)
        encrypt_radio.grid(row=0, column=0, padx=10)
        
        decrypt_radio = ttk.Radiobutton(mode_frame, text='🔓 Decrypt', 
                                       variable=self.mode_var, value='decrypt',
                                       command=self.update_ui_for_mode)
        decrypt_radio.grid(row=0, column=1, padx=10)
        
        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text='Input Text', padding="10")
        input_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, width=80, height=10, 
                                                     font=('Consolas', 11), wrap=tk.WORD)
        self.input_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.input_text.bind('<KeyRelease>', lambda e: self.update_button_states())
        
        # Key/Password frame
        key_frame = ttk.LabelFrame(main_frame, text='Password', padding="10")
        key_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        key_frame.columnconfigure(0, weight=1)
        
        self.key_label = ttk.Label(key_frame, 
                                    text='Enter password (required for encryption/decryption)')
        self.key_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.key_entry = ttk.Entry(key_frame, width=80, font=('Consolas', 11), show='*')
        self.key_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        self.key_entry.bind('<KeyRelease>', lambda e: self.update_button_states())
        
        self.show_pass_var = tk.BooleanVar(value=False)
        show_pass_check = ttk.Checkbutton(key_frame, text='Show password', 
                                         variable=self.show_pass_var,
                                         command=self.toggle_password_visibility)
        show_pass_check.grid(row=2, column=0, sticky=tk.W)
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, pady=(0, 15))
        
        self.run_btn = ttk.Button(button_frame, text='🔐 Encrypt', 
                                   command=self.do_action, width=18)
        self.run_btn.grid(row=0, column=0, padx=5)
        
        self.save_btn = ttk.Button(button_frame, text='💾 Save to Vault', 
                                   command=self.save_to_vault, width=18)
        self.save_btn.grid(row=0, column=1, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text='🗑️ Clear All', 
                               command=self.clear_all, width=18)
        self.clear_btn.grid(row=0, column=2, padx=5)
        
        self.copy_btn = ttk.Button(button_frame, text='📋 Copy Output', 
                             command=self.copy_output, width=18)
        self.copy_btn.grid(row=0, column=3, padx=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text='Output', padding="10")
        output_frame.grid(row=6, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(1, weight=1)
        
        self.output_status_label = ttk.Label(output_frame, text='Output', 
                                            font=('Segoe UI', 10, 'bold'))
        self.output_status_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.output_text = scrolledtext.ScrolledText(output_frame, width=80, height=12, 
                                                      font=('Consolas', 11), wrap=tk.WORD,
                                                      state='disabled')
        self.output_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Vault frame
        self.vault_frame = ttk.LabelFrame(main_frame, text='My Saved Messages Vault', padding="10")
        self.vault_frame.grid(row=7, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(15, 0))
        self.vault_frame.columnconfigure(0, weight=1)
        self.vault_frame.rowconfigure(1, weight=1)
        
        search_frame = ttk.Frame(self.vault_frame)
        search_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(search_frame, text='🔍 Search:').grid(row=0, column=0, padx=(0, 5))
        self.search_entry = ttk.Entry(search_frame, width=40)
        self.search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.search_entry.bind('<KeyRelease>', lambda e: self.refresh_vault())
        search_frame.columnconfigure(1, weight=1)
        
        vault_scroll_frame = ttk.Frame(self.vault_frame)
        vault_scroll_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vault_scroll_frame.columnconfigure(0, weight=1)
        vault_scroll_frame.rowconfigure(0, weight=1)

        vault_scrollbar = ttk.Scrollbar(vault_scroll_frame, takefocus=False)
        vault_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        self.vault_listbox = tk.Listbox(vault_scroll_frame, height=6, 
                                         font=('Consolas', 9),
                                         yscrollcommand=vault_scrollbar.set,
                                         takefocus=True)
        self.vault_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vault_scrollbar.config(command=self.vault_listbox.yview)
        self.vault_listbox.bind('<Double-Button-1>', lambda e: self.load_from_vault())

        self._setup_mousewheel_scrolling()
        
        vault_btn_frame = ttk.Frame(self.vault_frame)
        vault_btn_frame.grid(row=2, column=0, pady=(10, 0))
        
        load_btn = ttk.Button(vault_btn_frame, text='📂 Load Selected', 
                             command=self.load_from_vault, width=15)
        load_btn.grid(row=0, column=0, padx=5)
        
        delete_btn = ttk.Button(vault_btn_frame, text='🗑️ Delete Selected', 
                               command=self.delete_from_vault, width=15)
        delete_btn.grid(row=0, column=1, padx=5)
        
        refresh_btn = ttk.Button(vault_btn_frame, text='🔄 Refresh', 
                                command=self.refresh_vault, width=15)
        refresh_btn.grid(row=0, column=2, padx=5)
        
        # Status bar
        self.status_label = ttk.Label(main_frame, text='Ready', 
                                      relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.grid(row=8, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Configure grid weights
        main_frame.rowconfigure(3, weight=2)
        main_frame.rowconfigure(6, weight=3)
        main_frame.rowconfigure(7, weight=2)
        
        # Store last encrypted data
        self.last_cipher = None
        self.last_key = None
        self.last_plain = None
        
        self.vault_data = []
        
        self.update_login_ui()
        self.update_button_states()
    
    def _setup_mousewheel_scrolling(self):
        """Setup improved mousewheel scrolling"""
        def bind_mousewheel_for(widget):
            def on_enter(event):
                def on_scroll(e):
                    if e.num == 4:
                        widget.yview_scroll(-1, 'units')
                    elif e.num == 5:
                        widget.yview_scroll(1, 'units')
                    else:
                        widget.yview_scroll(-1 * int(e.delta / 120), 'units')
                    return 'break'
                
                widget.bind_all('<MouseWheel>', on_scroll)
                widget.bind_all('<Button-4>', on_scroll)
                widget.bind_all('<Button-5>', on_scroll)
            
            def on_leave(event):
                try:
                    widget.unbind_all('<MouseWheel>')
                    widget.unbind_all('<Button-4>')
                    widget.unbind_all('<Button-5>')
                except:
                    pass
            
            widget.bind('<Enter>', on_enter)
            widget.bind('<Leave>', on_leave)
        
        bind_mousewheel_for(self.input_text)
        bind_mousewheel_for(self.output_text)
        bind_mousewheel_for(self.vault_listbox)
    
    def init_database(self):
        """Initialize SQLite database with secure password storage"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create users table with salt field for secure password hashing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create vault table - plain_text is now encrypted or NULL
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                cipher_text TEXT NOT NULL,
                password_hint TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vault_user ON vault(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vault_label ON vault(label)')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Hash password securely using PBKDF2 if available"""
        if CRYPTO_MODE == "SECURE":
            password_hash, salt = crypto.hash_password_secure(password)
            return password_hash, salt
        else:
            # Fallback to SHA-256 (not recommended for production)
            import hashlib
            salt = "static_salt"  # In production, generate random salt
            hash_value = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
            return hash_value, salt
    
    def verify_password(self, password, stored_hash, salt):
        """Verify password securely"""
        if CRYPTO_MODE == "SECURE":
            return crypto.verify_password_secure(password, stored_hash, salt)
        else:
            import hashlib
            hash_value = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
            return hash_value == stored_hash
    
    def check_remembered_login(self):
        """Check if there's a remembered login"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = 'remembered_user_id'")
            row = cursor.fetchone()
            conn.close()
            
            if row:
                user_id = int(row[0])
                conn = sqlite3.connect(self.db_file)
                cursor = conn.cursor()
                cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
                user = cursor.fetchone()
                conn.close()
                
                if user:
                    self.current_user_id = user[0]
                    self.current_username = user[1]
        except:
            pass
    
    def show_login_dialog(self):
        """Show login/register dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title('Login / Register')
        dialog.geometry('450x300')
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text='Account Access', font=('Segoe UI', 14, 'bold')).pack(pady=(0, 20))
        
        # Username
        ttk.Label(frame, text='Username:').pack(anchor=tk.W)
        username_entry = ttk.Entry(frame, width=40)
        username_entry.pack(pady=(5, 15))
        
        # Password
        ttk.Label(frame, text='Password:').pack(anchor=tk.W)
        password_entry = ttk.Entry(frame, width=40, show='*')
        password_entry.pack(pady=(5, 15))
        
        # Remember me
        remember_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text='Remember me on this computer', 
                       variable=remember_var).pack(anchor=tk.W, pady=(0, 15))
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        def do_login():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            
            if not username or not password:
                messagebox.showwarning('Input Required', 'Please enter both username and password')
                return
            
            try:
                conn = sqlite3.connect(self.db_file)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, username, password_hash, password_salt FROM users 
                    WHERE username = ?
                ''', (username,))
                
                user = cursor.fetchone()
                conn.close()
                
                if user and self.verify_password(password, user[2], user[3]):
                    self.current_user_id = user[0]
                    self.current_username = user[1]
                    
                    if remember_var.get():
                        conn = sqlite3.connect(self.db_file)
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT OR REPLACE INTO settings (key, value) 
                            VALUES ('remembered_user_id', ?)
                        ''', (str(self.current_user_id),))
                        conn.commit()
                        conn.close()
                    
                    self.update_login_ui()
                    self.refresh_vault()
                    messagebox.showinfo('Success', f'Welcome back, {self.current_username}!')
                    dialog.destroy()
                else:
                    messagebox.showerror('Login Failed', 'Invalid username or password')
                    
            except Exception as e:
                messagebox.showerror('Error', f'Login error:\n{str(e)}')
        
        def do_register():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            
            if not username or not password:
                messagebox.showwarning('Input Required', 'Please enter both username and password')
                return
            
            if len(password) < 8:
                messagebox.showwarning('Weak Password', 
                                     'Password must be at least 8 characters for security')
                return
            
            try:
                conn = sqlite3.connect(self.db_file)
                cursor = conn.cursor()
                
                password_hash, salt = self.hash_password(password)
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                cursor.execute('''
                    INSERT INTO users (username, password_hash, password_salt, created_at)
                    VALUES (?, ?, ?, ?)
                ''', (username, password_hash, salt, now))
                
                self.current_user_id = cursor.lastrowid
                self.current_username = username
                
                conn.commit()
                conn.close()
                
                if remember_var.get():
                    conn = sqlite3.connect(self.db_file)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO settings (key, value) 
                        VALUES ('remembered_user_id', ?)
                    ''', (str(self.current_user_id),))
                    conn.commit()
                    conn.close()
                
                self.update_login_ui()
                self.refresh_vault()
                messagebox.showinfo('Success', f'Account created!\nWelcome, {self.current_username}!')
                dialog.destroy()
                
            except sqlite3.IntegrityError:
                messagebox.showerror('Registration Failed', 'Username already exists')
            except Exception as e:
                messagebox.showerror('Error', f'Registration error:\n{str(e)}')
        
        ttk.Button(btn_frame, text='🔐 Login', command=do_login, width=15).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text='📝 Register', command=do_register, width=15).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text='Cancel', command=dialog.destroy, width=15).grid(row=0, column=2, padx=5)
        
        username_entry.focus()
    
    def logout(self):
        """Logout current user"""
        confirm = messagebox.askyesno('Logout', f'Logout from {self.current_username}?')
        if not confirm:
            return
        
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM settings WHERE key = 'remembered_user_id'")
            conn.commit()
            conn.close()
        except:
            pass
        
        self.current_user_id = None
        self.current_username = None
        self.update_login_ui()
        self.refresh_vault()
        self.status_label.config(text='Logged out.')
    
    def update_login_ui(self):
        """Update UI based on login status"""
        if self.current_user_id:
            self.user_status_label.config(text=f'👤 {self.current_username}')
            self.login_btn.grid_remove()
            self.logout_btn.grid()
            self.vault_frame.grid()
        else:
            self.user_status_label.config(text='👤 Guest (Login to save)')
            self.logout_btn.grid_remove()
            self.login_btn.grid()
            self.vault_frame.grid_remove()
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_pass_var.get():
            self.key_entry.config(show='')
        else:
            self.key_entry.config(show='*')
    
    def update_ui_for_mode(self):
        """Update UI for encryption/decryption mode"""
        if self.mode_var.get() == 'encrypt':
            self.run_btn.config(text='🔐 Encrypt')
            self.status_label.config(text='Encryption mode')
        else:
            self.run_btn.config(text='🔓 Decrypt')
            self.status_label.config(text='Decryption mode')
        self.update_button_states()

    def update_button_states(self):
        """Enable/disable buttons based on state"""
        try:
            input_has = bool(self.input_text.get('1.0', 'end').strip())
        except:
            input_has = False
        try:
            output_has = bool(self.output_text.get('1.0', 'end').strip())
        except:
            output_has = False
        key_has = bool(self.key_entry.get().strip())

        # Run button - always needs password now
        if input_has and key_has:
            self.run_btn.state(['!disabled'])
        else:
            self.run_btn.state(['disabled'])

        # Save button
        if self.current_user_id and self.last_cipher:
            self.save_btn.state(['!disabled'])
        else:
            self.save_btn.state(['disabled'])

        # Copy button
        if output_has:
            self.copy_btn.state(['!disabled'])
        else:
            self.copy_btn.state(['disabled'])

        # Clear button
        if input_has or output_has or key_has or (self.last_cipher is not None):
            self.clear_btn.state(['!disabled'])
        else:
            self.clear_btn.state(['disabled'])
    
    def do_action(self):
        """Process encryption or decryption"""
        mode = self.mode_var.get()
        text = self.input_text.get('1.0', 'end').strip()
        password = self.key_entry.get().strip()
        
        if not text:
            messagebox.showwarning('Input Required', 'Please enter text')
            return
        
        if not password:
            messagebox.showwarning('Password Required', 'Please enter a password')
            return
        
        self.run_btn.state(['disabled'])
        self.status_label.config(text='Processing...')
        self.root.update_idletasks()

        try:
            if mode == 'encrypt':
                cipher, _ = crypto.encrypt(text, password=password)
                
                self.last_plain = text
                self.last_cipher = cipher
                self.last_key = password
                
                self.output_status_label.config(text='✓ ENCRYPTED', foreground='green')
                
                self.output_text.config(state='normal')
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', cipher)
                self.output_text.config(state='disabled')
                
                if self.current_user_id:
                    self.status_label.config(text='✓ Encrypted! Save to vault or copy output.')
                else:
                    self.status_label.config(text='✓ Encrypted! Login to save to vault.')
            else:
                plain = crypto.decrypt(text, password=password)
                
                self.last_plain = plain
                
                self.output_status_label.config(text='✓ DECRYPTED', foreground='blue')
                
                self.output_text.config(state='normal')
                self.output_text.delete('1.0', 'end')
                self.output_text.insert('1.0', plain)
                self.output_text.config(state='disabled')
                
                self.status_label.config(text='✓ Decryption successful!')
                
        except Exception as e:
            messagebox.showerror('Error', f'Operation failed:\n{str(e)}\n\nCheck your password.')
            self.status_label.config(text='✗ Error - check password')
        finally:
            self.run_btn.state(['!disabled'])
            self.update_button_states()
    
    def save_to_vault(self):
        """Save encrypted message to vault"""
        if not self.current_user_id:
            messagebox.showinfo('Login Required', 'Please login to save to vault.')
            self.show_login_dialog()
            return
        
        if not self.last_cipher:
            messagebox.showwarning('Nothing to Save', 'Please encrypt a message first')
            return
        
        # Ask for label and optional hint
        label = simpledialog.askstring('Save to Vault', 
                                      'Enter a label for this message:',
                                      parent=self.root)
        if not label:
            return
        
        hint = simpledialog.askstring('Password Hint (Optional)', 
                                     'Enter a hint for the password\n(stored unencrypted):',
                                     parent=self.root)
        
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Only store cipher text, not plaintext
            cursor.execute('''
                INSERT INTO vault (user_id, label, cipher_text, password_hint, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (self.current_user_id, label, self.last_cipher, hint, now, now))
            
            conn.commit()
            conn.close()
            
            self.refresh_vault()
            self.status_label.config(text=f'✓ Saved "{label}"')
            messagebox.showinfo('Saved', f'Message saved successfully!\n\nRemember your password!')
            self.update_button_states()
            
        except Exception as e:
            messagebox.showerror('Error', f'Save failed:\n{str(e)}')
    
    def refresh_vault(self):
        """Refresh vault listbox"""
        self.vault_listbox.delete(0, tk.END)
        
        if not self.current_user_id:
            self.vault_data = []
            return
        
        search_term = self.search_entry.get().strip()
        
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            if search_term:
                cursor.execute('''
                    SELECT id, label, created_at FROM vault 
                    WHERE user_id = ? AND label LIKE ? 
                    ORDER BY created_at DESC
                ''', (self.current_user_id, f'%{search_term}%'))
            else:
                cursor.execute('''
                    SELECT id, label, created_at FROM vault 
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                ''', (self.current_user_id,))
            
            self.vault_data = cursor.fetchall()
            conn.close()
            
            for row in self.vault_data:
                entry_id, label, created_at = row
                display_text = f"[{entry_id}] {created_at} - {label}"
                self.vault_listbox.insert(tk.END, display_text)
            
            count = len(self.vault_data)
            if count > 0:
                self.status_label.config(text=f'Vault: {count} message(s)')
            else:
                self.status_label.config(text='Vault is empty')
                
        except Exception as e:
            messagebox.showerror('Error', f'Load vault failed:\n{str(e)}')
    
    def load_from_vault(self):
        """Load selected message from vault"""
        selection = self.vault_listbox.curselection()
        if not selection:
            messagebox.showwarning('No Selection', 'Please select a message')
            return
        
        idx = selection[0]
        entry_id = self.vault_data[idx][0]
        
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT label, cipher_text, password_hint FROM vault 
                WHERE id = ? AND user_id = ?
            ''', (entry_id, self.current_user_id))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                label, cipher_text, hint = row
                
                self.input_text.delete('1.0', 'end')
                self.input_text.insert('1.0', cipher_text)
                
                self.mode_var.set('decrypt')
                self.update_ui_for_mode()
                
                hint_msg = f'\nPassword hint: {hint}' if hint else ''
                self.status_label.config(text=f'✓ Loaded "{label}". Enter password and decrypt.{hint_msg}')
                
                if hint:
                    messagebox.showinfo('Password Hint', f'Hint: {hint}')
                
                self.key_entry.focus()
                self.update_button_states()
                
        except Exception as e:
            messagebox.showerror('Error', f'Load failed:\n{str(e)}')
    
    def delete_from_vault(self):
        """Delete selected message"""
        selection = self.vault_listbox.curselection()
        if not selection:
            messagebox.showwarning('No Selection', 'Please select a message to delete')
            return
        
        idx = selection[0]
        entry_id, label, _ = self.vault_data[idx]
        
        confirm = messagebox.askyesno('Confirm Delete', 
                                      f'Delete "{label}"?\n\nThis cannot be undone!')
        if not confirm:
            return
        
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM vault WHERE id = ? AND user_id = ?', 
                         (entry_id, self.current_user_id))
            conn.commit()
            conn.close()
            
            self.refresh_vault()
            self.status_label.config(text=f'✓ Deleted "{label}"')
            
        except Exception as e:
            messagebox.showerror('Error', f'Delete failed:\n{str(e)}')
    
    def clear_all(self):
        """Clear all fields"""
        self.input_text.delete('1.0', 'end')
        self.key_entry.delete(0, 'end')
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', 'end')
        self.output_text.config(state='disabled')
        self.output_status_label.config(text='Output', foreground='black')
        self.last_cipher = None
        self.last_key = None
        self.last_plain = None
        self.status_label.config(text='Cleared')
        self.update_button_states()
    
    def copy_output(self):
        """Copy output to clipboard"""
        output = self.output_text.get('1.0', 'end').strip()
        if output:
            self.root.clipboard_clear()
            self.root.clipboard_append(output)
            self.status_label.config(text='✓ Copied to clipboard!')
        else:
            messagebox.showwarning('No Output', 'Nothing to copy')


if __name__ == '__main__':
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()