import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import sqlite3
import os
from datetime import datetime
import sys
from PIL import Image, ImageTk
import io

# Import encryption modules
try:
    import crypto_secure as crypto
    from crypto_secure import encrypt_file, decrypt_file
    CRYPTO_MODE = "SECURE"
except ImportError:
    import cyber as crypto
    CRYPTO_MODE = "SIMPLE"
    encrypt_file = decrypt_file = None

try:
    from crypto_audio import encrypt_audio, decrypt_audio, get_audio_info
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False

try:
    import pygame
    PYGAME_AVAILABLE = True
except ImportError:
    PYGAME_AVAILABLE = False

def resource_path(rel_path):
    """Get absolute path to resource"""
    if getattr(sys, 'frozen', False):
        base_path = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, rel_path)

DB_FILE = resource_path('securetext_vault.db')

# ============================================
# THEME CONFIGURATION - Consistent colors
# ============================================
class AppTheme:
    """Centralized theme configuration"""
    BG_COLOR = '#f5f5f5'
    ACCENT_PRIMARY = '#2196F3'
    ACCENT_SUCCESS = '#2e7d32'
    ACCENT_WARNING = '#f57c00'
    ACCENT_ERROR = '#d32f2f'
    TEXT_PRIMARY = '#212121'
    TEXT_SECONDARY = '#757575'
    CARD_BG = '#ffffff'
    BORDER_COLOR = '#e0e0e0'
    HOVER_COLOR = '#e3f2fd'
    
    # Scrollbar styling
    SCROLLBAR_BG = '#e0e0e0'
    SCROLLBAR_FG = '#9e9e9e'
    SCROLLBAR_ACTIVE = '#757575'

# ============================================
# CUSTOM SCROLLABLE FRAME
# ============================================
class ScrollableFrame(ttk.Frame):
    """Reusable scrollable frame with consistent styling"""
    
    def __init__(self, parent, **kwargs):
        ttk.Frame.__init__(self, parent, **kwargs)
        
        # Create canvas and scrollbar
        self.canvas = tk.Canvas(self, bg=AppTheme.BG_COLOR, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas, padding="15")
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor='nw')
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Bind canvas width adjustment
        self.canvas.bind('<Configure>', self._on_canvas_configure)
        
        # Mouse wheel scrolling
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Pack widgets
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)
    
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

# ============================================
# MAIN APPLICATION
# ============================================
class SecureTextProApp:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.init_database()
        self.check_remembered_login()
        self.setup_ui()
        self.update_login_ui()
        
        # Initialize audio player
        if PYGAME_AVAILABLE:
            pygame.mixer.init()
        
    def setup_window(self):
        """Configure main window"""
        title = 'SecureText Pro - Complete Encryption Suite'
        if CRYPTO_MODE == "SECURE":
            title += ' [AES-256]'
        self.root.title(title)
        self.root.geometry('1200x900')
        self.root.minsize(1000, 700)
        self.root.configure(bg=AppTheme.BG_COLOR)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom button styles
        style.configure('Accent.TButton', 
                       background=AppTheme.ACCENT_PRIMARY,
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       padding=10)

        # Ensure window is visible and on top when created (helps if it's hidden/minimized)
        try:
            self.root.update()
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass
    
    def setup_ui(self):
        """Setup main UI components"""
        # Top bar with user info
        self.create_top_bar()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 5))
        
        # Create tabs
        self.text_tab = ttk.Frame(self.notebook)
        self.file_tab = ttk.Frame(self.notebook)
        self.audio_tab = ttk.Frame(self.notebook)
        self.vault_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.text_tab, text='  📝 Text  ')
        self.notebook.add(self.file_tab, text='  🖼️ Images/Video  ')
        self.notebook.add(self.audio_tab, text='  🎵 Audio  ')
        self.notebook.add(self.vault_tab, text='  💾 My Vault  ')
        
        # Build tabs
        self.build_text_tab()
        self.build_file_tab()
        self.build_audio_tab()
        self.build_vault_tab()
        
        # Status bar
        self.create_status_bar()
        
        # Initialize state
        self.current_user_id = None
        self.current_username = None
        self.last_cipher = None
        self.vault_data = []
        self.current_audio_file = None
        self.current_image = None
    
    def create_top_bar(self):
        """Create top bar with user controls"""
        top_bar = ttk.Frame(self.root, relief=tk.RAISED, borderwidth=1)
        top_bar.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        # App title
        title_frame = ttk.Frame(top_bar)
        title_frame.pack(side=tk.LEFT, padx=15, pady=8)
        
        ttk.Label(title_frame, text='🔐 SecureText Pro', 
                 font=('Segoe UI', 14, 'bold'),
                 foreground=AppTheme.ACCENT_PRIMARY).pack()
        
        # Security indicator
        if CRYPTO_MODE == "SECURE":
            security_text = '✅ AES-256-GCM Encryption'
            security_color = AppTheme.ACCENT_SUCCESS
        else:
            security_text = '⚠️ Basic Mode'
            security_color = AppTheme.ACCENT_WARNING
        
        ttk.Label(title_frame, text=security_text,
                 font=('Segoe UI', 8),
                 foreground=security_color).pack()
        
        # User controls
        user_frame = ttk.Frame(top_bar)
        user_frame.pack(side=tk.RIGHT, padx=15, pady=8)
        
        self.user_status_label = ttk.Label(user_frame, text='👤 Guest Mode',
                                          font=('Segoe UI', 10))
        self.user_status_label.grid(row=0, column=0, padx=(0, 10))
        
        self.login_btn = ttk.Button(user_frame, text='🔐 Login',
                                    command=self.show_login_dialog, width=10)
        self.login_btn.grid(row=0, column=1, padx=2)
        
        self.logout_btn = ttk.Button(user_frame, text='🚪 Logout',
                                     command=self.logout, width=10)
        self.logout_btn.grid(row=0, column=2, padx=2)
    
    def create_status_bar(self):
        """Create bottom status bar"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text='Ready',
                                      relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X)
    
    # ========================================
    # TEXT ENCRYPTION TAB
    # ========================================
    def build_text_tab(self):
        """Build text encryption tab with scrollbar"""
        scroll_frame = ScrollableFrame(self.text_tab)
        scroll_frame.pack(fill=tk.BOTH, expand=True)
        
        main_frame = scroll_frame.scrollable_frame
        main_frame.columnconfigure(0, weight=1)
        
        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text='Operation Mode', padding="15")
        mode_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.text_mode_var = tk.StringVar(value='encrypt')
        ttk.Radiobutton(mode_frame, text='🔒 Encrypt', 
                       variable=self.text_mode_var, value='encrypt',
                       command=self.update_text_ui).grid(row=0, column=0, padx=20)
        ttk.Radiobutton(mode_frame, text='🔓 Decrypt',
                       variable=self.text_mode_var, value='decrypt',
                       command=self.update_text_ui).grid(row=0, column=1, padx=20)
        
        # Input
        input_frame = ttk.LabelFrame(main_frame, text='Input Text', padding="10")
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        
        self.text_input = scrolledtext.ScrolledText(input_frame, width=80, height=10,
                                                    font=('Consolas', 10), wrap=tk.WORD)
        self.text_input.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Password
        pass_frame = ttk.LabelFrame(main_frame, text='Password', padding="10")
        pass_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        pass_frame.columnconfigure(0, weight=1)
        
        self.text_pass = ttk.Entry(pass_frame, width=70, font=('Consolas', 10), show='*')
        self.text_pass.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.text_show_pass_var = tk.BooleanVar()
        ttk.Checkbutton(pass_frame, text='Show password',
                       variable=self.text_show_pass_var,
                       command=lambda: self.text_pass.config(
                           show='' if self.text_show_pass_var.get() else '*'
                       )).grid(row=1, column=0, sticky=tk.W)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=3, column=0, pady=(0, 15))
        
        self.text_action_btn = ttk.Button(btn_frame, text='🔒 Encrypt',
                                         command=self.do_text_action, width=15)
        self.text_action_btn.grid(row=0, column=0, padx=5)
        
        ttk.Button(btn_frame, text='💾 Save to Vault',
                  command=self.save_text_to_vault, width=15).grid(row=0, column=1, padx=5)
        
        ttk.Button(btn_frame, text='📋 Copy',
                  command=self.copy_text_output, width=12).grid(row=0, column=2, padx=5)
        
        ttk.Button(btn_frame, text='🗑️ Clear',
                  command=self.clear_text, width=12).grid(row=0, column=3, padx=5)
        
        # Output
        output_frame = ttk.LabelFrame(main_frame, text='Output', padding="10")
        output_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.text_output = scrolledtext.ScrolledText(output_frame, width=80, height=10,
                                                     font=('Consolas', 10), wrap=tk.WORD,
                                                     state='disabled')
        self.text_output.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        main_frame.rowconfigure(1, weight=2)
        main_frame.rowconfigure(4, weight=2)
    
    # ========================================
    # FILE (IMAGE/VIDEO) TAB
    # ========================================
    def build_file_tab(self):
        """Build file encryption tab with preview"""
        scroll_frame = ScrollableFrame(self.file_tab)
        scroll_frame.pack(fill=tk.BOTH, expand=True)
        
        main_frame = scroll_frame.scrollable_frame
        main_frame.columnconfigure(0, weight=1)
        
        # Title
        ttk.Label(main_frame, text='🖼️ Image & Video Encryption',
                 font=('Segoe UI', 16, 'bold')).grid(row=0, column=0, pady=(0, 5))
        
        ttk.Label(main_frame, text='Encrypt and decrypt images, videos, and documents',
                 font=('Segoe UI', 9), foreground=AppTheme.TEXT_SECONDARY).grid(row=1, column=0, pady=(0, 20))
        
        # File info card
        info_frame = ttk.LabelFrame(main_frame, text='Selected File', padding="15")
        info_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        info_frame.columnconfigure(1, weight=1)
        
        ttk.Label(info_frame, text='File:').grid(row=0, column=0, sticky=tk.W, pady=5)
        self.file_name_label = ttk.Label(info_frame, text='No file selected',
                                         foreground=AppTheme.TEXT_SECONDARY)
        self.file_name_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(info_frame, text='Size:').grid(row=1, column=0, sticky=tk.W, pady=5)
        self.file_size_label = ttk.Label(info_frame, text='--',
                                         foreground=AppTheme.TEXT_SECONDARY)
        self.file_size_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(info_frame, text='Type:').grid(row=2, column=0, sticky=tk.W, pady=5)
        self.file_type_label = ttk.Label(info_frame, text='--',
                                         foreground=AppTheme.TEXT_SECONDARY)
        self.file_type_label.grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        # Preview area
        preview_frame = ttk.LabelFrame(main_frame, text='Preview', padding="15")
        preview_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        preview_frame.columnconfigure(0, weight=1)
        preview_frame.rowconfigure(0, weight=1)
        
        self.file_preview_label = ttk.Label(preview_frame, text='Preview will appear here',
                                           foreground=AppTheme.TEXT_SECONDARY)
        self.file_preview_label.grid(row=0, column=0)
        
        # Selection buttons
        select_frame = ttk.Frame(main_frame)
        select_frame.grid(row=4, column=0, pady=(0, 15))
        
        ttk.Button(select_frame, text='📁 Select File to Encrypt',
                  command=self.select_file_encrypt, width=25).grid(row=0, column=0, padx=5)
        
        ttk.Button(select_frame, text='🔓 Select .enc File to Decrypt',
                  command=self.select_file_decrypt, width=25).grid(row=0, column=1, padx=5)
        
        # Password
        pass_frame = ttk.LabelFrame(main_frame, text='Password', padding="15")
        pass_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        pass_frame.columnconfigure(0, weight=1)
        
        self.file_pass = ttk.Entry(pass_frame, width=60, font=('Consolas', 10), show='*')
        self.file_pass.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.file_show_pass_var = tk.BooleanVar()
        ttk.Checkbutton(pass_frame, text='Show password',
                       variable=self.file_show_pass_var,
                       command=lambda: self.file_pass.config(
                           show='' if self.file_show_pass_var.get() else '*'
                       )).grid(row=1, column=0, sticky=tk.W)

        # Option: clear selection after encrypt
        self.clear_after_encrypt_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pass_frame, text='Clear selection after encryption',
                       variable=self.clear_after_encrypt_var).grid(row=2, column=0, sticky=tk.W, pady=(5,0))
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=6, column=0, pady=(0, 15))
        
        self.file_encrypt_btn = ttk.Button(action_frame, text='🔒 Encrypt File',
                                          command=self.encrypt_file_action,
                                          width=20, state='disabled')
        self.file_encrypt_btn.grid(row=0, column=0, padx=5)
        
        self.file_decrypt_btn = ttk.Button(action_frame, text='🔓 Decrypt File',
                                          command=self.decrypt_file_action,
                                          width=20, state='disabled')
        self.file_decrypt_btn.grid(row=0, column=1, padx=5)

        # Open / Clear buttons
        ttk.Button(action_frame, text='🔍 Open File', command=self.open_selected_file, width=12).grid(row=0, column=2, padx=5)
        ttk.Button(action_frame, text='🧹 Clear', command=self.clear_file_selection, width=12).grid(row=0, column=3, padx=5)
        
        # Status log
        log_frame = ttk.LabelFrame(main_frame, text='Status', padding="15")
        log_frame.grid(row=7, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.file_log = scrolledtext.ScrolledText(log_frame, width=70, height=8,
                                                  font=('Consolas', 9), wrap=tk.WORD,
                                                  state='disabled')
        self.file_log.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Store file info
        self.selected_file = None
        self.selected_file_mode = None
        
        # Configure weights
        main_frame.rowconfigure(3, weight=2)
        main_frame.rowconfigure(7, weight=1)
    
    # ========================================
    # AUDIO TAB
    # ========================================
    def build_audio_tab(self):
        """Build audio encryption tab with player"""
        scroll_frame = ScrollableFrame(self.audio_tab)
        scroll_frame.pack(fill=tk.BOTH, expand=True)
        
        main_frame = scroll_frame.scrollable_frame
        main_frame.columnconfigure(0, weight=1)
        
        # Title
        ttk.Label(main_frame, text='🎵 Audio Encryption & Player',
                 font=('Segoe UI', 16, 'bold')).grid(row=0, column=0, pady=(0, 5))
        
        ttk.Label(main_frame, text='Encrypt, decrypt, and play audio files',
                 font=('Segoe UI', 9), foreground=AppTheme.TEXT_SECONDARY).grid(row=1, column=0, pady=(0, 20))
        
        # Audio info card
        info_frame = ttk.LabelFrame(main_frame, text='Selected Audio', padding="15")
        info_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        info_frame.columnconfigure(1, weight=1)
        
        ttk.Label(info_frame, text='File:').grid(row=0, column=0, sticky=tk.W, pady=5)
        self.audio_name_label = ttk.Label(info_frame, text='No audio selected',
                                          foreground=AppTheme.TEXT_SECONDARY)
        self.audio_name_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(info_frame, text='Size:').grid(row=1, column=0, sticky=tk.W, pady=5)
        self.audio_size_label = ttk.Label(info_frame, text='--',
                                          foreground=AppTheme.TEXT_SECONDARY)
        self.audio_size_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(info_frame, text='Format:').grid(row=2, column=0, sticky=tk.W, pady=5)
        self.audio_format_label = ttk.Label(info_frame, text='--',
                                            foreground=AppTheme.TEXT_SECONDARY)
        self.audio_format_label.grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        # Audio player controls
        player_frame = ttk.LabelFrame(main_frame, text='🎧 Audio Player', padding="15")
        player_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        player_frame.columnconfigure(0, weight=1)
        
        # Player controls
        controls = ttk.Frame(player_frame)
        controls.grid(row=0, column=0, pady=10)
        
        self.audio_play_btn = ttk.Button(controls, text='▶️ Play',
                                         command=self.play_audio,
                                         width=12, state='disabled')
        self.audio_play_btn.grid(row=0, column=0, padx=5)
        
        self.audio_pause_btn = ttk.Button(controls, text='⏸️ Pause',
                                          command=self.pause_audio,
                                          width=12, state='disabled')
        self.audio_pause_btn.grid(row=0, column=1, padx=5)
        
        self.audio_stop_btn = ttk.Button(controls, text='⏹️ Stop',
                                         command=self.stop_audio,
                                         width=12, state='disabled')
        self.audio_stop_btn.grid(row=0, column=2, padx=5)
        
        # Volume control
        volume_frame = ttk.Frame(player_frame)
        volume_frame.grid(row=1, column=0, pady=5)
        
        ttk.Label(volume_frame, text='🔊 Volume:').grid(row=0, column=0, padx=5)
        self.volume_var = tk.DoubleVar(value=70)
        volume_slider = ttk.Scale(volume_frame, from_=0, to=100,
                                  orient=tk.HORIZONTAL, variable=self.volume_var,
                                  command=self.update_volume, length=200)
        volume_slider.grid(row=0, column=1, padx=5)
        self.volume_label = ttk.Label(volume_frame, text='70%')
        self.volume_label.grid(row=0, column=2, padx=5)
        
        # Selection buttons
        select_frame = ttk.Frame(main_frame)
        select_frame.grid(row=4, column=0, pady=(0, 15))
        
        ttk.Button(select_frame, text='📁 Select Audio to Encrypt',
                  command=self.select_audio_encrypt, width=25).grid(row=0, column=0, padx=5)
        
        ttk.Button(select_frame, text='🔓 Select .aenc to Decrypt',
                  command=self.select_audio_decrypt, width=25).grid(row=0, column=1, padx=5)
        
        # Password
        pass_frame = ttk.LabelFrame(main_frame, text='Password', padding="15")
        pass_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        pass_frame.columnconfigure(0, weight=1)
        
        self.audio_pass = ttk.Entry(pass_frame, width=60, font=('Consolas', 10), show='*')
        self.audio_pass.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.audio_show_pass_var = tk.BooleanVar()
        ttk.Checkbutton(pass_frame, text='Show password',
                       variable=self.audio_show_pass_var,
                       command=lambda: self.audio_pass.config(
                           show='' if self.audio_show_pass_var.get() else '*'
                       )).grid(row=1, column=0, sticky=tk.W)
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=6, column=0, pady=(0, 15))
        
        self.audio_encrypt_btn = ttk.Button(action_frame, text='🔒 Encrypt Audio',
                                           command=self.encrypt_audio_action,
                                           width=20, state='disabled')
        self.audio_encrypt_btn.grid(row=0, column=0, padx=5)
        
        self.audio_decrypt_btn = ttk.Button(action_frame, text='🔓 Decrypt Audio',
                                           command=self.decrypt_audio_action,
                                           width=20, state='disabled')
        self.audio_decrypt_btn.grid(row=0, column=1, padx=5)
        
        # Status log
        log_frame = ttk.LabelFrame(main_frame, text='Status', padding="15")
        log_frame.grid(row=7, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.audio_log = scrolledtext.ScrolledText(log_frame, width=70, height=8,
                                                   font=('Consolas', 9), wrap=tk.WORD,
                                                   state='disabled')
        self.audio_log.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initialize
        self.selected_audio = None
        self.selected_audio_mode = None
        self.audio_playing = False
        
        # Add initial message
        if not AUDIO_AVAILABLE:
            self.log_audio("⚠️ Audio encryption module not available")
        elif not PYGAME_AVAILABLE:
            self.log_audio("⚠️ Pygame not installed - audio playback unavailable\nInstall with: pip install pygame")
        else:
            self.log_audio("✅ Audio encryption and playback ready!")
        
        # Configure weights
        main_frame.rowconfigure(7, weight=1)
    
    # ========================================
    # VAULT TAB
    # ========================================
    def build_vault_tab(self):
        """Build vault management tab"""
        main_frame = ttk.Frame(self.vault_tab, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)
        
        # Title
        ttk.Label(main_frame, text='💾 My Encrypted Vault',
                 font=('Segoe UI', 16, 'bold')).grid(row=0, column=0, pady=(0, 5))
        
        ttk.Label(main_frame, text='Securely store and manage your encrypted messages',
                 font=('Segoe UI', 9), foreground=AppTheme.TEXT_SECONDARY).grid(row=1, column=0, pady=(0, 20))
        
        # Search
        search_frame = ttk.Frame(main_frame)
        search_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        search_frame.columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text='🔍 Search:', font=('Segoe UI', 10)).grid(row=0, column=0, padx=(0, 10))
        self.vault_search = ttk.Entry(search_frame, width=40, font=('Segoe UI', 10))
        self.vault_search.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.vault_search.bind('<KeyRelease>', lambda e: self.refresh_vault())
        
        ttk.Button(search_frame, text='🔄 Refresh', command=self.refresh_vault, width=12).grid(row=0, column=2, padx=(10, 0))
        
        # Vault list
        list_frame = ttk.LabelFrame(main_frame, text='Saved Messages', padding="15")
        list_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        vault_scroll = ttk.Scrollbar(list_frame)
        vault_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.vault_listbox = tk.Listbox(list_frame, height=15, font=('Consolas', 10),
                                        yscrollcommand=vault_scroll.set)
        self.vault_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vault_scroll.config(command=self.vault_listbox.yview)
        self.vault_listbox.bind('<Double-Button-1>', lambda e: self.load_from_vault())
        
        # Vault controls
        controls_frame = ttk.Frame(main_frame)
        controls_frame.grid(row=4, column=0, pady=(0, 10))
        
        ttk.Button(controls_frame, text='📂 Load', command=self.load_from_vault, width=15).grid(row=0, column=0, padx=5)
        ttk.Button(controls_frame, text='🗑️ Delete', command=self.delete_from_vault, width=15).grid(row=0, column=1, padx=5)
        ttk.Button(controls_frame, text='📊 Export', command=self.export_vault, width=15).grid(row=0, column=2, padx=5)
        
        # Statistics
        stats_frame = ttk.LabelFrame(main_frame, text='Vault Statistics', padding="15")
        stats_frame.grid(row=5, column=0, sticky=(tk.W, tk.E))
        
        self.vault_stats_label = ttk.Label(stats_frame, text='No messages in vault',
                                          font=('Segoe UI', 10))
        self.vault_stats_label.pack()
        
        # Configure weights
        main_frame.rowconfigure(3, weight=1)
    
    # ========================================
    # DATABASE FUNCTIONS
    # ========================================
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
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
        
        conn.commit()
        conn.close()
    
    def check_remembered_login(self):
        """Check for remembered login"""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = 'remembered_user_id'")
            row = cursor.fetchone()
            conn.close()
            
            if row:
                user_id = int(row[0])
                conn = sqlite3.connect(DB_FILE)
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
        dialog.geometry('450x320')
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text='🔐 Account Access', 
                 font=('Segoe UI', 16, 'bold')).pack(pady=(0, 20))

        ttk.Label(frame, text='Username:').pack(anchor=tk.W)
        username_entry = ttk.Entry(frame, width=40, font=('Segoe UI', 10))
        username_entry.pack(pady=(5, 15))

        ttk.Label(frame, text='Password:').pack(anchor=tk.W)
        password_entry = ttk.Entry(frame, width=40, font=('Segoe UI', 10), show='*')
        password_entry.pack(pady=(5, 15))

        remember_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text='Remember me on this computer', 
                       variable=remember_var).pack(anchor=tk.W, pady=(0, 15))

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=15)

        def do_login():
            username = username_entry.get().strip()
            password = password_entry.get().strip()

            if not username or not password:
                messagebox.showwarning('Input Required', 'Please enter both username and password')
                return

            try:
                conn = sqlite3.connect(DB_FILE)
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
                        conn = sqlite3.connect(DB_FILE)
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT OR REPLACE INTO settings (key, value) 
                            VALUES ('remembered_user_id', ?)
                        ''', (str(self.current_user_id),))
                        conn.commit()
                        conn.close()

                    self.update_login_ui()
                    self.refresh_vault()
                    messagebox.showinfo('Success', f'Welcome back, {self.current_username}! 👋')
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
                                     'Password must be at least 8 characters')
                return

            try:
                conn = sqlite3.connect(DB_FILE)
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
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO settings (key, value) 
                        VALUES ('remembered_user_id', ?)
                    ''', (str(self.current_user_id),))
                    conn.commit()
                    conn.close()

                self.update_login_ui()
                self.refresh_vault()
                messagebox.showinfo('Success', f'Account created! 🎉\nWelcome, {self.current_username}!')
                dialog.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror('Registration Failed', 'Username already exists')
            except Exception as e:
                messagebox.showerror('Error', f'Registration error:\n{str(e)}')

        ttk.Button(btn_frame, text='🔓 Login', command=do_login, width=12).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text='📝 Register', command=do_register, width=12).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text='❌ Cancel', command=dialog.destroy, width=12).grid(row=0, column=2, padx=5)

        username_entry.focus()
        password_entry.bind('<Return>', lambda e: do_login())

    def logout(self):
        """Log out the current user"""
        try:
            self.current_user_id = None
            self.current_username = None

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM settings WHERE key = 'remembered_user_id'")
            conn.commit()
            conn.close()

            self.update_login_ui()
            self.refresh_vault()
            messagebox.showinfo('Logged out', 'You have been logged out')
        except Exception as e:
            messagebox.showerror('Error', f'Logout failed:\n{str(e)}')
    
    # ========================================
    # TEXT ENCRYPTION FUNCTIONS
    # ========================================
    def update_text_ui(self):
        """Update text UI based on mode"""
        if self.text_mode_var.get() == 'encrypt':
            self.text_action_btn.config(text='🔒 Encrypt')
        else:
            self.text_action_btn.config(text='🔓 Decrypt')
    
    def do_text_action(self):
        """Perform text encryption/decryption"""
        mode = self.text_mode_var.get()
        text = self.text_input.get('1.0', 'end').strip()
        password = self.text_pass.get().strip()
        
        if not text:
            messagebox.showwarning('Input Required', 'Please enter text')
            return
        
        if not password:
            messagebox.showwarning('Password Required', 'Please enter a password')
            return
        
        try:
            if mode == 'encrypt':
                cipher, _ = crypto.encrypt(text, password=password)
                self.last_cipher = cipher
                
                self.text_output.config(state='normal')
                self.text_output.delete('1.0', 'end')
                self.text_output.insert('1.0', cipher)
                self.text_output.config(state='disabled')
                
                self.status_label.config(text='✅ Text encrypted successfully!')
                messagebox.showinfo('Success', 'Text encrypted!\n\nYou can now copy it or save to vault.')
            else:
                plain = crypto.decrypt(text, password=password)
                
                self.text_output.config(state='normal')
                self.text_output.delete('1.0', 'end')
                self.text_output.insert('1.0', plain)
                self.text_output.config(state='disabled')
                
                self.status_label.config(text='✅ Text decrypted successfully!')
                messagebox.showinfo('Success', 'Text decrypted successfully!')
        
        except Exception as e:
            messagebox.showerror('Error', f'Operation failed:\n{str(e)}\n\nPlease check your password.')
            self.status_label.config(text='❌ Operation failed')
    
    def save_text_to_vault(self):
        """Save encrypted text to vault"""
        if not self.current_user_id:
            messagebox.showinfo('Login Required', 'Please login to save to vault.')
            self.show_login_dialog()
            return
        
        if not self.last_cipher:
            messagebox.showwarning('Nothing to Save', 'Please encrypt a message first')
            return
        
        label = simpledialog.askstring('Save to Vault', 'Enter a label for this message:')
        if not label:
            return
        
        hint = simpledialog.askstring('Password Hint (Optional)', 
                                     'Enter a hint for the password\n(stored unencrypted):')
        
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute('''
                INSERT INTO vault (user_id, label, cipher_text, password_hint, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (self.current_user_id, label, self.last_cipher, hint, now, now))
            
            conn.commit()
            conn.close()
            
            self.refresh_vault()
            self.status_label.config(text=f'✅ Deleted "{label}"')
            messagebox.showinfo('Deleted', f'"{label}" has been deleted')
        
        except Exception as e:
            messagebox.showerror('Error', f'Delete failed:\n{str(e)}')
    # Additional UI helpers (moved from module scope into the class)
    def copy_text_output(self):
        """Copy text output to clipboard"""
        output = self.text_output.get('1.0', 'end').strip()
        if output:
            self.root.clipboard_clear()
            self.root.clipboard_append(output)
            self.status_label.config(text='✅ Copied to clipboard!')
            messagebox.showinfo('Copied', 'Output copied to clipboard!')
        else:
            messagebox.showwarning('No Output', 'Nothing to copy')

    def clear_text(self):
        """Clear all text fields"""
        self.text_input.delete('1.0', 'end')
        self.text_pass.delete(0, 'end')
        self.text_output.config(state='normal')
        self.text_output.delete('1.0', 'end')
        self.text_output.config(state='disabled')
        self.status_label.config(text='Cleared')

    # ========================================
    # Helper / Utility Methods
    # ========================================
    def format_size(self, size_bytes: int) -> str:
        """Return a human-readable file size"""
        try:
            if size_bytes < 1024:
                return f"{size_bytes} B"
            for unit in ['KB', 'MB', 'GB', 'TB']:
                size_bytes /= 1024.0
                if size_bytes < 1024.0:
                    return f"{size_bytes:.2f} {unit}"
        except Exception:
            pass
        return str(size_bytes)

    def hash_password(self, password: str):
        """Hash password using crypto module if available, else fallback."""
        try:
            if hasattr(crypto, 'hash_password_secure'):
                return crypto.hash_password_secure(password)
        except Exception:
            pass

        # Fallback: simple salted SHA256 (not recommended for production)
        import hashlib, os
        salt = os.urandom(16).hex()
        h = hashlib.sha256((salt + password).encode()).hexdigest()
        return h, salt

    def verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verify password using crypto module if available, else fallback."""
        try:
            if hasattr(crypto, 'verify_password_secure'):
                return crypto.verify_password_secure(password, stored_hash, salt)
        except Exception:
            pass

        import hashlib
        return hashlib.sha256((salt + password).encode()).hexdigest() == stored_hash

    def update_login_ui(self):
        """Update UI elements related to login state"""
        if getattr(self, 'current_user_id', None):
            self.user_status_label.config(text=f'👤 {self.current_username}')
            try:
                self.login_btn.state(['disabled'])
                self.logout_btn.state(['!disabled'])
            except Exception:
                pass
        else:
            self.user_status_label.config(text='👤 Guest Mode')
            try:
                self.login_btn.state(['!disabled'])
                self.logout_btn.state(['disabled'])
            except Exception:
                pass

    def export_vault(self):
        """Export vault entries to a CSV file"""
        if not getattr(self, 'current_user_id', None):
            messagebox.showinfo('Login Required', 'Please login to export your vault.')
            self.show_login_dialog()
            return

        file_path = filedialog.asksaveasfilename(title='Export Vault', defaultextension='.csv',
                                                 filetypes=[('CSV', '*.csv'), ('All Files', '*.*')])
        if not file_path:
            return

        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('SELECT label, cipher_text, password_hint, created_at FROM vault WHERE user_id = ?',
                           (self.current_user_id,))
            rows = cursor.fetchall()
            conn.close()

            import csv
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['label', 'cipher_text', 'password_hint', 'created_at'])
                for r in rows:
                    writer.writerow(r)

            messagebox.showinfo('Exported', f'Vault exported to: {file_path}')
        except Exception as e:
            messagebox.showerror('Error', f'Export failed:\n{str(e)}')

    # ========================================
    # VAULT HELPERS
    # ========================================
    def refresh_vault(self):
        """Refresh vault list"""
        try:
            self.vault_listbox.delete(0, tk.END)
            if not getattr(self, 'current_user_id', None):
                self.vault_data = []
                self.vault_stats_label.config(text='Please login to view vault')
                return

            search_term = self.vault_search.get().strip() if hasattr(self, 'vault_search') else ''
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            if search_term:
                cursor.execute('''SELECT id, label, created_at FROM vault WHERE user_id = ? AND label LIKE ? ORDER BY created_at DESC''',
                               (self.current_user_id, f'%{search_term}%'))
            else:
                cursor.execute('''SELECT id, label, created_at FROM vault WHERE user_id = ? ORDER BY created_at DESC''',
                               (self.current_user_id,))
            self.vault_data = cursor.fetchall()
            conn.close()

            for row in self.vault_data:
                entry_id, label, created_at = row
                display_text = f"[{entry_id}] {created_at} - {label}"
                self.vault_listbox.insert(tk.END, display_text)

            self.vault_stats_label.config(text=f'💾 {len(self.vault_data)} message(s) in vault')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to load vault:\n{str(e)}')

    def load_from_vault(self):
        """Load selected message from vault into text tab"""
        try:
            sel = self.vault_listbox.curselection()
            if not sel:
                messagebox.showwarning('No Selection', 'Please select a message')
                return
            idx = sel[0]
            entry_id = self.vault_data[idx][0]
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('SELECT label, cipher_text, password_hint FROM vault WHERE id = ? AND user_id = ?', (entry_id, self.current_user_id))
            row = cursor.fetchone()
            conn.close()
            if row:
                label, cipher_text, hint = row
                # switch to text tab
                try:
                    self.notebook.select(self.text_tab)
                except Exception:
                    pass
                self.text_input.delete('1.0', 'end')
                self.text_input.insert('1.0', cipher_text)
                self.text_mode_var.set('decrypt')
                self.update_text_ui()
                if hint:
                    messagebox.showinfo('Password Hint', f'Hint: {hint}')
                else:
                    messagebox.showinfo('Loaded', f'Loaded "{label}"\n\nEnter password and decrypt')
                self.text_pass.focus()
        except Exception as e:
            messagebox.showerror('Error', f'Failed to load:\n{str(e)}')

    def delete_from_vault(self):
        """Delete selected vault entry"""
        try:
            sel = self.vault_listbox.curselection()
            if not sel:
                messagebox.showwarning('No Selection', 'Please select a message to delete')
                return
            idx = sel[0]
            entry_id, label, _ = self.vault_data[idx]
            confirm = messagebox.askyesno('Confirm Delete', f'Delete "{label}"?\n\nThis cannot be undone!')
            if not confirm:
                return
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM vault WHERE id = ? AND user_id = ?', (entry_id, self.current_user_id))
            conn.commit()
            conn.close()
            self.refresh_vault()
        except Exception as e:
            messagebox.showerror('Error', f'Delete failed:\n{str(e)}')

    # ========================================
    # AUDIO PLAYBACK HELPERS
    # ========================================
    def play_audio(self):
        """Play selected audio or show message if unavailable"""
        if not PYGAME_AVAILABLE:
            messagebox.showerror('Feature Unavailable', 'Audio playback requires pygame')
            return

        path = getattr(self, 'selected_audio', None) or getattr(self, 'current_audio_file', None)
        if not path or path.endswith('.aenc'):
            messagebox.showwarning('Cannot Play', 'Please select/decrypt an audio file first')
            return

        try:
            pygame.mixer.music.load(path)
            pygame.mixer.music.play()
            self.audio_playing = True
            try:
                self.audio_pause_btn.state(['!disabled'])
                self.audio_stop_btn.state(['!disabled'])
            except Exception:
                pass
            self.log_audio(f"\n▶️ Playing: {os.path.basename(path)}")
            self.status_label.config(text='▶️ Playing audio...')
        except Exception as e:
            messagebox.showerror('Playback Error', f'Failed to play audio:\n{str(e)}')

    def pause_audio(self):
        """Pause or resume audio playback"""
        if not PYGAME_AVAILABLE:
            return
        try:
            if getattr(self, 'audio_playing', False):
                pygame.mixer.music.pause()
                self.audio_playing = False
                try:
                    self.audio_pause_btn.config(text='▶️ Resume')
                except Exception:
                    pass
                self.log_audio('⏸️ Paused')
                self.status_label.config(text='⏸️ Audio paused')
            else:
                pygame.mixer.music.unpause()
                self.audio_playing = True
                try:
                    self.audio_pause_btn.config(text='⏸️ Pause')
                except Exception:
                    pass
                self.log_audio('▶️ Resumed')
                self.status_label.config(text='▶️ Audio resumed')
        except Exception as e:
            messagebox.showerror('Error', f'Pause/resume failed:\n{str(e)}')

    def stop_audio(self):
        """Stop audio playback"""
        if not PYGAME_AVAILABLE:
            return
        try:
            pygame.mixer.music.stop()
            self.audio_playing = False
            try:
                self.audio_pause_btn.config(text='⏸️ Pause')
                self.audio_pause_btn.state(['disabled'])
                self.audio_stop_btn.state(['disabled'])
            except Exception:
                pass
            self.log_audio('⏹️ Stopped')
            self.status_label.config(text='⏹️ Audio stopped')
        except Exception as e:
            messagebox.showerror('Error', f'Stop failed:\n{str(e)}')

    def update_volume(self, val):
        """Update audio volume (UI callback)"""
        try:
            if PYGAME_AVAILABLE:
                volume = float(val) / 100.0
                pygame.mixer.music.set_volume(volume)
                self.volume_label.config(text=f'{int(float(val))}%')
        except Exception:
            pass

    def log_audio(self, message):
        """Append a message to the audio log widget"""
        try:
            self.audio_log.config(state='normal')
            self.audio_log.insert(tk.END, message + '\n')
            self.audio_log.see(tk.END)
            self.audio_log.config(state='disabled')
        except Exception:
            pass

    def encrypt_audio_action(self):
        """Encrypt selected audio (wrapper)"""
        if not AUDIO_AVAILABLE:
            messagebox.showerror('Feature Unavailable', 'Audio encryption requires crypto_audio module')
            return

        if not getattr(self, 'selected_audio', None):
            messagebox.showwarning('No Audio', 'Please select an audio file first')
            return

        password = self.audio_pass.get().strip() if hasattr(self, 'audio_pass') else ''
        if not password:
            messagebox.showwarning('Password Required', 'Please enter a password')
            return

        try:
            self.log_audio("\n🔄 Encrypting audio...")
            self.status_label.config(text='Encrypting audio...')
            self.root.update_idletasks()

            out = encrypt_audio(password, self.selected_audio)
            self.log_audio(f"✅ Audio encrypted successfully! Saved as: {os.path.basename(out)}")
            messagebox.showinfo('Success', f'Audio encrypted and saved: {os.path.basename(out)}')
        except Exception as e:
            self.log_audio(f"❌ Audio encryption failed: {str(e)}")
            messagebox.showerror('Error', f'Audio encryption failed:\n{str(e)}')

    def decrypt_audio_action(self):
        """Decrypt selected audio (wrapper)"""
        if not AUDIO_AVAILABLE:
            messagebox.showerror('Feature Unavailable', 'Audio decryption requires crypto_audio module')
            return

        if not getattr(self, 'selected_audio', None):
            messagebox.showwarning('No Audio', 'Please select an encrypted audio file first')
            return

        password = self.audio_pass.get().strip() if hasattr(self, 'audio_pass') else ''
        if not password:
            messagebox.showwarning('Password Required', 'Please enter the decryption password')
            return

        try:
            self.log_audio("\n🔄 Decrypting audio...")
            self.status_label.config(text='Decrypting audio...')
            self.root.update_idletasks()

            out = decrypt_audio(password, self.selected_audio)
            self.log_audio(f"✅ Audio decrypted successfully! Restored as: {os.path.basename(out)}")
            messagebox.showinfo('Success', f'Audio decrypted: {os.path.basename(out)}')

            # Remember restored file and auto-play it
            try:
                self.current_audio_file = out
                self.selected_audio = out
                self.selected_audio_mode = 'decrypted'
                if PYGAME_AVAILABLE:
                    try:
                        self.audio_play_btn.state(['!disabled'])
                    except Exception:
                        pass
                    # start playback automatically
                    try:
                        self.play_audio()
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception as e:
            self.log_audio(f"❌ Audio decryption failed: {str(e)}")
            messagebox.showerror('Error', f'Audio decryption failed:\n{str(e)}')

    def display_audio_info(self, file_path):
        """Display audio file information in the UI"""
        try:
            name = os.path.basename(file_path)
            size = None
            try:
                size = os.path.getsize(file_path)
            except Exception:
                # fallback to crypto helper if available
                if AUDIO_AVAILABLE:
                    info = get_audio_info(file_path)
                    size = info.get('size') if isinstance(info, dict) else None

            size_str = self.format_size(size) if isinstance(size, int) else ('--' if size is None else str(size))
            ext = os.path.splitext(name)[1].lower() or '--'

            self.audio_name_label.config(text=name, foreground=AppTheme.TEXT_PRIMARY)
            self.audio_size_label.config(text=size_str, foreground=AppTheme.TEXT_PRIMARY)
            self.audio_format_label.config(text=ext, foreground=AppTheme.TEXT_PRIMARY)

            # Enable/disable play button depending on availability and file type
            try:
                if PYGAME_AVAILABLE and not file_path.endswith('.aenc'):
                    self.audio_play_btn.state(['!disabled'])
                else:
                    self.audio_play_btn.state(['disabled'])
            except Exception:
                pass
        except Exception:
            # If anything goes wrong, show a simple fallback
            try:
                self.audio_name_label.config(text='No audio selected', foreground=AppTheme.TEXT_SECONDARY)
                self.audio_size_label.config(text='--', foreground=AppTheme.TEXT_SECONDARY)
                self.audio_format_label.config(text='--', foreground=AppTheme.TEXT_SECONDARY)
            except Exception:
                pass

    # ========================================
    # FILE ENCRYPTION FUNCTIONS
    # ========================================
    def select_file_encrypt(self):
        """Select file to encrypt"""
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[
                ("Images", "*.jpg *.jpeg *.png *.gif *.bmp *.webp"),
                ("Videos", "*.mp4 *.avi *.mkv *.mov *.wmv *.flv"),
                ("Documents", "*.pdf *.doc *.docx *.txt *.xlsx"),
                ("All Files", "*.*")
            ]
        )

        if file_path:
            self.selected_file = file_path
            self.selected_file_mode = 'encrypt'
            self.display_file_info(file_path)
            self.load_file_preview(file_path)
            self.file_encrypt_btn.state(['!disabled'])
            self.file_decrypt_btn.state(['disabled'])
            self.log_file(f"✅ Selected for encryption:\n{os.path.basename(file_path)}")

    def select_file_decrypt(self):
        """Select encrypted file to decrypt"""
        file_path = filedialog.askopenfilename(
            title="Select .enc file to decrypt",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )

        if file_path:
            self.selected_file = file_path
            self.selected_file_mode = 'decrypt'
            self.display_file_info(file_path)
            self.file_decrypt_btn.state(['!disabled'])
            self.file_encrypt_btn.state(['disabled'])
            self.log_file(f"✅ Selected for decryption:\n{os.path.basename(file_path)}")

    def display_file_info(self, file_path):
        """Display file information"""
        try:
            size = os.path.getsize(file_path)
            size_str = self.format_size(size)
            name = os.path.basename(file_path)
            ext = os.path.splitext(name)[1] or "No extension"

            self.file_name_label.config(text=name, foreground=AppTheme.TEXT_PRIMARY)
            self.file_size_label.config(text=size_str, foreground=AppTheme.TEXT_PRIMARY)
            self.file_type_label.config(text=ext, foreground=AppTheme.TEXT_PRIMARY)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to read file info:\n{str(e)}')

    def load_file_preview(self, file_path):
        """Load image preview"""
        try:
            if file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
                img = Image.open(file_path)
                img.thumbnail((400, 400))
                photo = ImageTk.PhotoImage(img)
                self.file_preview_label.config(image=photo, text='')
                self.file_preview_label.image = photo
            else:
                ext = os.path.splitext(file_path)[1].upper()
                self.file_preview_label.config(
                    text=f'📄 {ext} File\n(Preview not available)',
                    image='',
                    foreground=AppTheme.TEXT_SECONDARY
                )
        except Exception as e:
            self.file_preview_label.config(text=f'Preview unavailable\n{str(e)}', image='')

    def encrypt_file_action(self):
        """Encrypt selected file"""
        if not self.selected_file:
            messagebox.showwarning('No File', 'Please select a file first')
            return

        password = self.file_pass.get().strip()
        if not password:
            messagebox.showwarning('Password Required', 'Please enter a password')
            return

        if len(password) < 6:
            messagebox.showwarning('Weak Password', 'Password should be at least 6 characters')
            return

        try:
            self.log_file("\n🔄 Encrypting file...")
            self.status_label.config(text='Encrypting...')
            self.root.update_idletasks()

            output_path = encrypt_file(password, self.selected_file)

            self.log_file(f"✅ File encrypted successfully!")
            self.log_file(f"📁 Saved as: {os.path.basename(output_path)}")
            self.log_file(f"\n⚠️ REMEMBER YOUR PASSWORD!")

            self.status_label.config(text='✅ File encrypted successfully!')
            messagebox.showinfo('Success', 
                              f'File encrypted!\n\nSaved as: {os.path.basename(output_path)}\n\nRemember your password!')

            self.file_pass.delete(0, tk.END)

            # Optionally clear selection after encryption
            if getattr(self, 'clear_after_encrypt_var', None) and self.clear_after_encrypt_var.get():
                self.clear_file_selection()

        except Exception as e:
            self.log_file(f"❌ Encryption failed: {str(e)}")
            self.status_label.config(text='❌ Encryption failed')
            messagebox.showerror('Error', f'Encryption failed:\n{str(e)}')

    def decrypt_file_action(self):
        """Decrypt selected file"""
        if not self.selected_file:
            messagebox.showwarning('No File', 'Please select an encrypted file first')
            return

        password = self.file_pass.get().strip()
        if not password:
            messagebox.showwarning('Password Required', 'Please enter the decryption password')
            return

        try:
            self.log_file("\n🔄 Decrypting file...")
            self.status_label.config(text='Decrypting...')
            self.root.update_idletasks()

            output_path = decrypt_file(password, self.selected_file)

            self.log_file(f"✅ File decrypted successfully!")
            self.log_file(f"📁 Restored as: {os.path.basename(output_path)}")

            self.status_label.config(text='✅ File decrypted successfully!')

            # Try to load preview
            self.load_file_preview(output_path)

            messagebox.showinfo('Success', 
                              f'File decrypted!\n\nRestored as: {os.path.basename(output_path)}')

            self.file_pass.delete(0, tk.END)

            # After decryption, set the selected file to the restored output so user can preview/open it
            try:
                self.selected_file = output_path
                self.selected_file_mode = 'decrypted'
                # enable open button if exists
                try:
                    self.file_encrypt_btn.state(['disabled'])
                    self.file_decrypt_btn.state(['disabled'])
                except Exception:
                    pass
            except Exception:
                pass

        except Exception as e:
            self.log_file(f"❌ Decryption failed: {str(e)}")
            self.status_label.config(text='❌ Decryption failed')
            messagebox.showerror('Error', 
                               f'Decryption failed:\n{str(e)}\n\nCheck your password!')

    def log_file(self, message):
        """Log message to file log"""
        self.file_log.config(state='normal')
        self.file_log.insert(tk.END, message + '\n')
        self.file_log.see(tk.END)
        self.file_log.config(state='disabled')

    def clear_file_selection(self):
        """Clear the selected file and reset preview & UI"""
        try:
            self.selected_file = None
            self.selected_file_mode = None
            self.file_name_label.config(text='No file selected', foreground=AppTheme.TEXT_SECONDARY)
            self.file_size_label.config(text='--', foreground=AppTheme.TEXT_SECONDARY)
            self.file_type_label.config(text='--', foreground=AppTheme.TEXT_SECONDARY)
            try:
                self.file_preview_label.config(text='Preview will appear here', image='')
                self.file_preview_label.image = None
            except Exception:
                pass
            try:
                self.file_encrypt_btn.state(['disabled'])
                self.file_decrypt_btn.state(['disabled'])
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror('Error', f'Failed to clear selection:\n{str(e)}')

    def open_selected_file(self):
        """Open the selected file (or decrypted output) with the default app (Windows)"""
        path = getattr(self, 'selected_file', None)
        if not path:
            messagebox.showwarning('No File', 'No file selected to open')
            return
        try:
            if sys.platform.startswith('win'):
                os.startfile(path)
            else:
                # POSIX: try xdg-open or open
                import subprocess
                opener = 'xdg-open' if sys.platform.startswith('linux') else 'open'
                subprocess.Popen([opener, path])
        except Exception as e:
            messagebox.showerror('Open Failed', f'Could not open file:\n{str(e)}')

    # ========================================
    # AUDIO ENCRYPTION FUNCTIONS
    # ========================================
    def select_audio_encrypt(self):
        """Select audio to encrypt"""
        file_path = filedialog.askopenfilename(
            title="Select audio to encrypt",
            filetypes=[
                ("Audio Files", "*.mp3 *.wav *.ogg *.flac *.m4a *.aac"),
                ("All Files", "*.*")
            ]
        )

        if file_path:
            self.selected_audio = file_path
            self.selected_audio_mode = 'encrypt'
            self.display_audio_info(file_path)
            self.audio_encrypt_btn.state(['!disabled'])
            self.audio_decrypt_btn.state(['disabled'])

            # Enable playback if available
            if PYGAME_AVAILABLE and not file_path.endswith('.aenc'):
                self.audio_play_btn.state(['!disabled'])

            self.log_audio(f"\n✅ Selected for encryption:\n{os.path.basename(file_path)}")

    def select_audio_decrypt(self):
        """Select encrypted audio to decrypt"""
        file_path = filedialog.askopenfilename(
            title="Select .aenc file to decrypt",
            filetypes=[("Encrypted Audio", "*.aenc"), ("All Files", "*.*")]
        )

        if file_path:
            self.selected_audio = file_path
            self.selected_audio_mode = 'decrypt'
            self.display_audio_info(file_path)
            self.audio_decrypt_btn.state(['!disabled'])
            self.audio_encrypt_btn.state(['disabled'])
            self.audio_play_btn.state(['disabled'])

            self.log_audio(f"\n✅ Selected for decryption:\n{os.path.basename(file_path)}")
        

# Clean module entrypoint: run the app when executed directly
def main():
    root = tk.Tk()
    app = SecureTextProApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()