import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
import math
import secrets
import string
import hashlib
import requests
from datetime import datetime
import json
import os
from cryptography.fernet import Fernet

COLORS = {
    'primary': '#2c3e50',
    'secondary': '#3498db',
    'success': '#2ecc71',
    'danger': '#e74c3c',
    'warning': '#f39c12',
    'info': '#9b59b6',
    'dark': '#34495e',
    'light': '#ecf0f1',
    'bg': '#f8f9fa',
    'card': '#ffffff',
    'border': '#dfe6e9'
}

FONTS = {
    'h1': ('Segoe UI', 18, 'bold'),
    'h2': ('Segoe UI', 14, 'bold'),
    'h3': ('Segoe UI', 12, 'bold'),
    'body': ('Segoe UI', 10),
    'small': ('Segoe UI', 9),
    'mono': ('Courier New', 10)
}

class PasswordAnalyzer:
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.common_passwords = self.load_common_passwords()
        self.history_file = "password_history.enc"
        self.load_history()

    def load_common_passwords(self):
        common_passwords = set()
        try:
            with open('rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip().lower()
                    if password:
                        common_passwords.add(password)
        except FileNotFoundError:
            common_passwords = {
                '123456', 'password', '123456789', '12345', 'qwerty',
                '12345678', '111111', '1234567', 'dragon', '123123',
                'baseball', 'abc123', 'football', 'monkey', 'letmein'
            }
        return common_passwords

    def encrypt_history(self, history):
        return self.cipher.encrypt(json.dumps(history).encode())

    def decrypt_history(self, encrypted_data):
        return json.loads(self.cipher.decrypt(encrypted_data).decode())

    def load_history(self):
        self.history = []
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'rb') as f:
                    encrypted = f.read()
                    self.history = self.decrypt_history(encrypted)
        except:
            self.history = []

        for entry in self.history:
            if 'action' not in entry:
                entry['action'] = 'check'
        return self.history

    def save_history(self):
        try:
            encrypted = self.encrypt_history(self.history)
            with open(self.history_file, 'wb') as f:
                f.write(encrypted)
            os.chmod(self.history_file, 0o600)
        except:
            pass

    def save_to_history(self, password, strength_score, leaks_found=False, action="check", pwned_count=0):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        password_preview = password[:2] + "***" + password[-1:] if len(password) > 3 else "***"

        entry = {
            'timestamp': timestamp,
            'password_preview': password_preview,
            'strength_score': strength_score,
            'leaks_found': leaks_found,
            'pwned_count': pwned_count,
            'length': len(password),
            'entropy': self.calculate_entropy(password),
            'action': action
        }

        self.history.append(entry)
        if len(self.history) > 100:
            self.history = self.history[-100:]
        self.save_history()
        return entry

    def calculate_entropy(self, password):
        if not password:
            return 0
        char_sets = {
            'lower': bool(re.search(r'[a-z]', password)),
            'upper': bool(re.search(r'[A-Z]', password)),
            'digits': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/]', password))
        }
        pool_size = 0
        if char_sets['lower']: pool_size += 26
        if char_sets['upper']: pool_size += 26
        if char_sets['digits']: pool_size += 10
        if char_sets['special']: pool_size += 20
        if pool_size == 0:
            return 0
        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 1)

    def get_entropy_level(self, entropy):
        if entropy == 0:
            return "Нет данных", COLORS['dark'], 0
        elif entropy < 28:
            return "Очень слабая", COLORS['danger'], 1
        elif entropy < 36:
            return "Слабая", '#ff6b6b', 2
        elif entropy < 60:
            return "Средняя", COLORS['warning'], 3
        elif entropy < 80:
            return "Сильная", '#1dd1a1', 4
        else:
            return "Очень сильная", COLORS['success'], 5

    def detailed_analysis(self, password):
        tips = []
        warnings = []
        recommendations = []

        if not password:
            return "Введите пароль", COLORS['dark'], tips, warnings, recommendations, 0, "Нет данных"

        length = len(password)
        if length < 8:
            warnings.append(f"🔴 Слишком короткий ({length} символов)")
        elif length < 12:
            tips.append(f"🟡 Длина {length} символов")
        else:
            tips.append(f"🟢 Отличная длина ({length} символов)")

        char_types = []
        if re.search(r'[a-z]', password): char_types.append("строчные")
        if re.search(r'[A-Z]', password): char_types.append("заглавные")
        if re.search(r'\d', password): char_types.append("цифры")
        if re.search(r'[!@#$%^&*]', password): char_types.append("спецсимволы")

        diversity = len(char_types)
        if diversity == 1:
            warnings.append("🔴 Только 1 тип символов")
        elif diversity == 2:
            warnings.append("🟡 Только 2 типа символов")
        elif diversity == 3:
            tips.append("🟡 3 типа символов")
        else:
            tips.append("🟢 4 типа символов")

        if password.lower() in self.common_passwords:
            warnings.append("🔴 В списке самых ненадёжных паролей")

        entropy = self.calculate_entropy(password)
        entropy_level, entropy_color, _ = self.get_entropy_level(entropy)

        if warnings:
            assessment = "Требует улучшения"
            color = COLORS['warning']
        elif tips and not warnings:
            assessment = "Хороший пароль"
            color = COLORS['success']
        else:
            assessment = "Отличный пароль!"
            color = "#27ae60"

        recommendations.append("💡 Рекомендации:")
        if length < 12:
            recommendations.append("• Увеличьте длину до 12+ символов")
        if diversity < 4:
            recommendations.append("• Добавьте разные типы символов")
        if not warnings and diversity == 4 and length >= 12:
            recommendations.append("• Ваш пароль достаточно надёжен!")

        return assessment, color, tips, warnings, recommendations, entropy, entropy_level

    def check_strength(self, password):
        if not password:
            return "введите пароль", 0, ""

        if password.lower() in self.common_passwords:
            return "в топе утекших", 1, "менее секунды"

        entropy = self.calculate_entropy(password)

        if entropy < 28:
            time_to_crack = "менее минуты"
            strength = "очень слабый"
            score = 1
        elif entropy < 36:
            time_to_crack = "от минут до часов"
            strength = "слабый"
            score = 2
        elif entropy < 60:
            time_to_crack = "от дней до месяцев"
            strength = "средний"
            score = 3
        elif entropy < 80:
            time_to_crack = "от лет до столетий"
            strength = "сильный"
            score = 4
        else:
            time_to_crack = "тысячи лет"
            strength = "очень сильный"
            score = 5

        return strength, score, time_to_crack

    def check_pwned_api(self, password):
        try:
            sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1password[:5], sha1password[5:]

            headers = {
                'User-Agent': 'PasswordAnalyzer/1.0',
                'Accept': 'text/plain'
            }

            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers=headers,
                timeout=10,
                verify=True
            )

            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return int(count)
                return 0
            elif response.status_code == 429:
                print("Слишком много запросов к API. Попробуйте позже.")
                return -1
            else:
                print(f"Ошибка API: {response.status_code}")
                return -1

        except requests.exceptions.RequestException as e:
            print(f"Ошибка сети: {e}")
            return -1

    def get_stats(self):
        if not self.history:
            return {
                'total_checks': 0,
                'avg_strength': 0,
                'best_strength': 0,
                'worst_strength': 0,
                'leaks_found': 0,
                'common_length': 0,
                'checks_today': 0,
                'total_generated': 0
            }

        checks = []
        today = datetime.now().strftime("%Y-%m-%d")
        checks_today = 0
        leaks_found = 0
        total_generated = 0
        strengths = []
        lengths = []

        for entry in self.history:
            action = entry.get('action', 'check')
            strength = entry.get('strength_score', 0)
            length = entry.get('length', 0)

            if action == 'check':
                checks.append(entry)
                strengths.append(strength)
                lengths.append(length)

                timestamp = entry.get('timestamp', '')
                if timestamp.startswith(today):
                    checks_today += 1

                if entry.get('leaks_found', False):
                    leaks_found += 1
            elif action == 'generate':
                total_generated += 1

        if not strengths:
            return {
                'total_checks': len(checks),
                'avg_strength': 0,
                'best_strength': 0,
                'worst_strength': 0,
                'leaks_found': leaks_found,
                'common_length': 0,
                'checks_today': checks_today,
                'total_generated': total_generated
            }

        if lengths:
            common_length = max(set(lengths), key=lengths.count)
        else:
            common_length = 0

        return {
            'total_checks': len(checks),
            'avg_strength': round(sum(strengths) / len(strengths), 1),
            'best_strength': max(strengths),
            'worst_strength': min(strengths),
            'leaks_found': leaks_found,
            'common_length': common_length,
            'checks_today': checks_today,
            'total_generated': total_generated
        }

class PasswordGenerator:
    def __init__(self):
        self.stats = {'total_generated': 0}

    def generate_random(self, length=12, use_letters=True, use_digits=True, use_special=True):
        chars = ""
        if use_letters:
            chars += string.ascii_letters
        if use_digits:
            chars += string.digits
        if use_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?/"
        if not chars:
            raise ValueError("Не выбрано ни одного типа символов для генерации пароля.")

        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.stats['total_generated'] += 1
        return password

    def generate_passphrase(self, word_count=4, separator="-", capitalize=True, add_number=True):
        words = [
            "red", "blue", "green", "white", "black", "yellow",
            "house", "city", "street", "park", "forest", "river", "mountain", "field",
            "sun", "moon", "star", "water", "fire", "air", "earth",
            "book", "table", "chair", "window", "door", "key", "clock", "map",
            "apple", "cat", "dog", "car", "time", "person", "year", "day", "way", "thing",
            "man", "woman", "child", "world", "life", "hand", "part", "eye", "friend", "place",
            "work", "week", "month", "money", "family", "school", "student", "teacher", "country", "home",
            "food", "music", "night", "morning", "love", "heart", "dream", "light", "dark", "cold",
            "hot", "big", "small", "new", "old", "good", "bad", "happy", "sad", "beautiful"
        ]

        chosen_words = [secrets.choice(words) for _ in range(word_count)]

        if capitalize:
            chosen_words = [word.capitalize() for word in chosen_words]

        passphrase = separator.join(chosen_words)

        if add_number:
            passphrase += str(secrets.randbelow(90) + 10)

        self.stats['total_generated'] += 1
        return passphrase

    def generate_pattern(self, pattern="Aaddss"):
        char_map = {
            'A': string.ascii_uppercase,
            'a': string.ascii_lowercase,
            'd': string.digits,
            's': "!@#$%^&*()_+-=[]{}|;:,.<>?/",
            'n': string.digits,
            'l': string.ascii_lowercase,
            'u': string.ascii_uppercase
        }

        password = []
        for char in pattern:
            if char in char_map:
                password.append(secrets.choice(char_map[char]))
            else:
                password.append(char)

        result = ''.join(password)
        self.stats['total_generated'] += 1
        return result

class ModernButton(tk.Button):
    def __init__(self, parent, **kwargs):
        bg = kwargs.pop('bg', COLORS['secondary'])
        fg = kwargs.pop('fg', 'white')
        font = kwargs.pop('font', FONTS['body'])
        padx = kwargs.pop('padx', 12)
        pady = kwargs.pop('pady', 8)

        super().__init__(parent,
            bg=bg, fg=fg, font=font,
            padx=padx, pady=pady,
            relief=tk.FLAT, cursor='hand2',
            activebackground=self._lighten_color(bg),
            **kwargs
        )

    def _lighten_color(self, color, factor=0.15):
        try:
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            r = min(255, int(r * (1 + factor)))
            g = min(255, int(g * (1 + factor)))
            b = min(255, int(b * (1 + factor)))
            return f'#{r:02x}{g:02x}{b:02x}'
        except:
            return color

class PasswordApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🔐 Анализатор паролей")
        self.window.geometry("900x750")
        self.window.configure(bg=COLORS['bg'])
        self.center_window()

        self.analyzer = PasswordAnalyzer()
        self.generator = PasswordGenerator()

        self.setup_styles()
        self.setup_ui()

    def center_window(self):
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure('Custom.TNotebook', background=COLORS['bg'])
        style.configure('Custom.TNotebook.Tab',
                       background=COLORS['light'],
                       foreground=COLORS['dark'],
                       padding=[20, 8],
                       font=FONTS['body'])
        style.map('Custom.TNotebook.Tab',
                 background=[('selected', COLORS['primary'])],
                 foreground=[('selected', 'white')])

        style.configure("green.Horizontal.TProgressbar",
                       background=COLORS['success'],
                       troughcolor=COLORS['light'])

        style.configure("Treeview",
                       background=COLORS['card'],
                       foreground=COLORS['dark'],
                       fieldbackground=COLORS['card'],
                       borderwidth=0,
                       font=FONTS['small'])
        style.configure("Treeview.Heading",
                       background=COLORS['light'],
                       foreground=COLORS['primary'],
                       font=FONTS['h3'],
                       relief=tk.FLAT)
        style.map("Treeview", background=[('selected', COLORS['secondary'])])

    def setup_ui(self):
        header = tk.Frame(self.window, bg=COLORS['primary'], height=100)
        header.pack(fill="x", pady=(0, 15))
        header.pack_propagate(False)

        tk.Label(header,
            text="🔐 АНАЛИЗАТОР И ГЕНЕРАТОР ПАРОЛЕЙ",
            font=FONTS['h1'],
            bg=COLORS['primary'],
            fg='white'
        ).pack(expand=True)

        tk.Label(header,
            text="Повышайте безопасность ваших аккаунтов",
            font=FONTS['small'],
            bg=COLORS['primary'],
            fg=COLORS['light']
        ).pack(pady=(0, 15))

        self.notebook = ttk.Notebook(self.window, style='Custom.TNotebook')
        self.notebook.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.tab_analyze = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.tab_generate = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.tab_stats = tk.Frame(self.notebook, bg=COLORS['bg'])

        self.notebook.add(self.tab_analyze, text="🔍 АНАЛИЗ ПАРОЛЯ")
        self.notebook.add(self.tab_generate, text="⚡ ГЕНЕРАЦИЯ ПАРОЛЕЙ")
        self.notebook.add(self.tab_stats, text="📊 СТАТИСТИКА")

        self.setup_analysis_tab()
        self.setup_generation_tab()
        self.setup_stats_tab()

        self.setup_status_bar()

    def setup_analysis_tab(self):
        main_frame = tk.Frame(self.tab_analyze, bg=COLORS['bg'])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        input_card = tk.Frame(main_frame, bg=COLORS['card'], relief=tk.RAISED, bd=1)
        input_card.pack(fill="x", pady=(0, 20))

        tk.Label(input_card,
            text="ВВЕДИТЕ ПАРОЛЬ ДЛЯ ПРОВЕРКИ",
            font=FONTS['h2'],
            bg=COLORS['card'],
            fg=COLORS['primary'],
            padx=20,
            pady=15
        ).pack(anchor="w")

        input_content = tk.Frame(input_card, bg=COLORS['card'], padx=20)
        input_content.pack(fill="x", pady=(0, 20))

        entry_frame = tk.Frame(input_content, bg=COLORS['card'])
        entry_frame.pack(fill="x", pady=(0, 15))

        tk.Label(entry_frame,
            text="Пароль:",
            font=FONTS['h3'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left")

        self.password_var = tk.StringVar()
        self.password_var.trace_add('write', lambda *args: self.real_time_check())

        self.password_entry = tk.Entry(entry_frame,
            textvariable=self.password_var,
            show="*",
            font=("Segoe UI", 12),
            width=40,
            relief=tk.FLAT,
            bg='white',
            fg=COLORS['primary'],
            insertbackground=COLORS['primary']
        )
        self.password_entry.pack(side="left", padx=10)

        btn_frame = tk.Frame(input_content, bg=COLORS['card'])
        btn_frame.pack(fill="x")

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(btn_frame,
            text="👁 Показать пароль",
            variable=self.show_var,
            command=self.toggle_password,
            font=FONTS['small'],
            bg=COLORS['card'],
            fg=COLORS['dark'],
            selectcolor=COLORS['card']
        ).pack(side="left", padx=5)

        ModernButton(btn_frame,
            text="🧹 Очистить",
            bg=COLORS['dark'],
            command=self.clear_password,
            padx=10,
            pady=5
        ).pack(side="left", padx=5)

        ModernButton(btn_frame,
            text="🔍 Проверить утечки",
            bg=COLORS['info'],
            command=self.check_pwned,
            padx=10,
            pady=5
        ).pack(side="left", padx=5)

        results_card = tk.Frame(main_frame, bg=COLORS['card'], relief=tk.RAISED, bd=1)
        results_card.pack(fill="both", expand=True)

        tk.Label(results_card,
            text="РЕЗУЛЬТАТЫ АНАЛИЗА",
            font=FONTS['h2'],
            bg=COLORS['card'],
            fg=COLORS['primary'],
            padx=20,
            pady=15
        ).pack(anchor="w")

        results_content = tk.Frame(results_card, bg=COLORS['card'], padx=20)
        results_content.pack(fill="both", expand=True, pady=(0, 20))

        top_row = tk.Frame(results_content, bg=COLORS['card'])
        top_row.pack(fill="x", pady=(0, 20))

        left_col = tk.Frame(top_row, bg=COLORS['card'])
        left_col.pack(side="left", fill="both", expand=True)

        tk.Label(left_col,
            text="ОБЩАЯ ОЦЕНКА",
            font=FONTS['h3'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(anchor="w")

        self.strength_label = tk.Label(left_col,
            text="Введите пароль",
            font=("Segoe UI", 24, "bold"),
            bg=COLORS['card'],
            fg=COLORS['dark']
        )
        self.strength_label.pack(anchor="w", pady=(5, 0))

        self.time_label = tk.Label(left_col,
            text="",
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        )
        self.time_label.pack(anchor="w", pady=(2, 0))

        self.strength_progress = ttk.Progressbar(left_col,
            length=250,
            maximum=5,
            style="green.Horizontal.TProgressbar"
        )
        self.strength_progress.pack(anchor="w", pady=(10, 0))

        right_col = tk.Frame(top_row, bg=COLORS['card'])
        right_col.pack(side="right", fill="both", expand=True)

        tk.Label(right_col,
            text="ЭНТРОПИЯ ПАРОЛЯ",
            font=FONTS['h3'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(anchor="w")

        self.entropy_value_label = tk.Label(right_col,
            text="0.0",
            font=("Segoe UI", 24, "bold"),
            bg=COLORS['card'],
            fg=COLORS['primary']
        )
        self.entropy_value_label.pack(anchor="w", pady=(5, 0))

        self.entropy_level_label = tk.Label(right_col,
            text="Нет данных",
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        )
        self.entropy_level_label.pack(anchor="w")

        scale_frame = tk.Frame(results_content, bg=COLORS['card'])
        scale_frame.pack(fill="x", pady=(0, 20))

        tk.Label(scale_frame,
            text="ШКАЛА ЭНТРОПИИ:",
            font=FONTS['h3'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(anchor="w")

        self.entropy_scale_label = tk.Label(scale_frame,
            text="",
            font=FONTS['mono'],
            bg=COLORS['card'],
            fg=COLORS['dark'],
            justify=tk.LEFT
        )
        self.entropy_scale_label.pack(fill="x", pady=(5, 0))

        analysis_frame = tk.Frame(results_content, bg=COLORS['card'])
        analysis_frame.pack(fill="both", expand=True)

        tk.Label(analysis_frame,
            text="ДЕТАЛЬНЫЙ АНАЛИЗ",
            font=FONTS['h3'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(anchor="w")

        self.analysis_text = scrolledtext.ScrolledText(analysis_frame,
            wrap=tk.WORD,
            font=FONTS['body'],
            bg='white',
            fg=COLORS['dark'],
            relief=tk.FLAT,
            borderwidth=1,
            height=10
        )
        self.analysis_text.pack(fill="both", expand=True, pady=(5, 0))
        self.analysis_text.config(state=tk.DISABLED)

        self.pwned_result = tk.Label(results_content,
            text="",
            font=FONTS['body'],
            bg=COLORS['card'],
            justify=tk.LEFT,
            wraplength=600
        )
        self.pwned_result.pack(fill="x", pady=(20, 0))

    def setup_generation_tab(self):
        main_frame = tk.Frame(self.tab_generate, bg=COLORS['bg'])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        settings_card = tk.Frame(main_frame, bg=COLORS['card'], relief=tk.RAISED, bd=1)
        settings_card.pack(fill="x", pady=(0, 20))

        tk.Label(settings_card,
            text="НАСТРОЙКИ ГЕНЕРАЦИИ ПАРОЛЕЙ",
            font=FONTS['h2'],
            bg=COLORS['card'],
            fg=COLORS['primary'],
            padx=20,
            pady=15
        ).pack(anchor="w")

        settings_content = tk.Frame(settings_card, bg=COLORS['card'], padx=20)
        settings_content.pack(fill="x", pady=(0, 20))

        type_frame = tk.Frame(settings_content, bg=COLORS['card'])
        type_frame.pack(fill="x", pady=(0, 15))

        tk.Label(type_frame,
            text="Тип пароля:",
            font=FONTS['h3'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left")

        self.gen_type = tk.StringVar(value="random")

        types = [
            ("🔢 Случайный", "random"),
            ("🗣️ Мнемоническая фраза", "passphrase"),
            ("📐 По шаблону", "pattern")
        ]

        for text, value in types:
            tk.Radiobutton(type_frame,
                text=text,
                variable=self.gen_type,
                value=value,
                font=FONTS['body'],
                bg=COLORS['card'],
                fg=COLORS['dark'],
                selectcolor=COLORS['card'],
                command=self.update_gen_settings
            ).pack(side="left", padx=10)

        self.random_frame = tk.Frame(settings_content, bg=COLORS['card'])

        tk.Label(self.random_frame,
            text="Длина:",
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left")

        self.random_length = tk.IntVar(value=14)
        tk.Spinbox(self.random_frame,
            from_=8,
            to=32,
            textvariable=self.random_length,
            width=5,
            font=FONTS['body']
        ).pack(side="left", padx=5)

        self.use_upper = tk.BooleanVar(value=True)
        tk.Checkbutton(self.random_frame,
            text="A-Z",
            variable=self.use_upper,
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left", padx=10)

        self.use_digits = tk.BooleanVar(value=True)
        tk.Checkbutton(self.random_frame,
            text="0-9",
            variable=self.use_digits,
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left", padx=10)

        self.use_special = tk.BooleanVar(value=True)
        tk.Checkbutton(self.random_frame,
            text="!@#$",
            variable=self.use_special,
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left", padx=10)

        self.passphrase_frame = tk.Frame(settings_content, bg=COLORS['card'])

        tk.Label(self.passphrase_frame,
            text="Слов:",
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left")

        self.phrase_words = tk.IntVar(value=4)
        tk.Spinbox(self.passphrase_frame,
            from_=3,
            to=8,
            textvariable=self.phrase_words,
            width=3,
            font=FONTS['body']
        ).pack(side="left", padx=5)

        tk.Label(self.passphrase_frame,
            text="Разделитель:",
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left", padx=(10, 5))

        self.phrase_separator = tk.StringVar(value="-")
        tk.Entry(self.passphrase_frame,
            textvariable=self.phrase_separator,
            width=3,
            font=FONTS['body']
        ).pack(side="left")

        self.phrase_capitalize = tk.BooleanVar(value=True)
        tk.Checkbutton(self.passphrase_frame,
            text="Заглавные",
            variable=self.phrase_capitalize,
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left", padx=10)

        self.phrase_add_number = tk.BooleanVar(value=True)
        tk.Checkbutton(self.passphrase_frame,
            text="+Число",
            variable=self.phrase_add_number,
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left", padx=10)

        self.pattern_frame = tk.Frame(settings_content, bg=COLORS['card'])

        tk.Label(self.pattern_frame,
            text="Шаблон (A=ЗАГЛАВНАЯ, a=строчная, d=цифра, s=символ):",
            font=FONTS['body'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        ).pack(side="left")

        self.pattern_text = tk.StringVar(value="Aaddss")
        tk.Entry(self.pattern_frame,
            textvariable=self.pattern_text,
            width=10,
            font=FONTS['body']
        ).pack(side="left", padx=5)

        self.update_gen_settings()

        ModernButton(settings_content,
            text="⚡ СГЕНЕРИРОВАТЬ ПАРОЛЬ",
            bg=COLORS['success'],
            font=("Segoe UI", 11, "bold"),
            command=self.generate_password,
            padx=20,
            pady=12
        ).pack(pady=(15, 0))

        result_card = tk.Frame(main_frame, bg=COLORS['card'], relief=tk.RAISED, bd=1)
        result_card.pack(fill="both", expand=True)

        tk.Label(result_card,
            text="СГЕНЕРИРОВАННЫЙ ПАРОЛЬ",
            font=FONTS['h2'],
            bg=COLORS['card'],
            fg=COLORS['primary'],
            padx=20,
            pady=15
        ).pack(anchor="w")

        result_content = tk.Frame(result_card, bg=COLORS['card'], padx=20)
        result_content.pack(fill="both", expand=True, pady=(0, 20))

        self.generated_password_var = tk.StringVar()

        password_frame = tk.Frame(result_content, bg=COLORS['card'])
        password_frame.pack(fill="x", pady=(0, 20))

        self.generated_entry = tk.Entry(password_frame,
            textvariable=self.generated_password_var,
            font=("Courier New", 14, "bold"),
            justify='center',
            relief=tk.FLAT,
            bg='white',
            fg=COLORS['primary'],
            state='readonly'
        )
        self.generated_entry.pack(fill="x", pady=10)

        action_frame = tk.Frame(result_content, bg=COLORS['card'])
        action_frame.pack(fill="x")

        ModernButton(action_frame,
            text="📋 Копировать",
            bg=COLORS['info'],
            command=self.copy_generated,
            padx=15
        ).pack(side="left", padx=5)

        ModernButton(action_frame,
            text="🔍 Проверить этот пароль",
            bg=COLORS['secondary'],
            command=self.check_generated_password,
            padx=15
        ).pack(side="left", padx=5)

        ModernButton(action_frame,
            text="🔄 Сгенерировать ещё",
            bg=COLORS['warning'],
            command=self.generate_password,
            padx=15
        ).pack(side="left", padx=5)

        stats_frame = tk.Frame(result_content, bg=COLORS['card'])
        stats_frame.pack(fill="x", pady=(20, 0))

        self.gen_stats_label = tk.Label(stats_frame,
            text="Сгенерировано паролей: 0",
            font=FONTS['small'],
            bg=COLORS['card'],
            fg=COLORS['dark']
        )
        self.gen_stats_label.pack(anchor="w")

    def setup_stats_tab(self):
        main_frame = tk.Frame(self.tab_stats, bg=COLORS['bg'])
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        stats_card = tk.Frame(main_frame, bg=COLORS['card'], relief=tk.RAISED, bd=1)
        stats_card.pack(fill="x", pady=(0, 20))

        tk.Label(stats_card,
            text="СТАТИСТИКА ИСПОЛЬЗОВАНИЯ",
            font=FONTS['h2'],
            bg=COLORS['card'],
            fg=COLORS['primary'],
            padx=20,
            pady=15
        ).pack(anchor="w")

        stats_content = tk.Frame(stats_card, bg=COLORS['card'], padx=20)
        stats_content.pack(fill="x", pady=(0, 20))

        self.stats_grid = tk.Frame(stats_content, bg=COLORS['card'])
        self.stats_grid.pack(fill="x")

        self.update_stats_display_init()

        history_card = tk.Frame(main_frame, bg=COLORS['card'], relief=tk.RAISED, bd=1)
        history_card.pack(fill="both", expand=True)

        tk.Label(history_card,
            text="ИСТОРИЯ ПРОВЕРОК И ГЕНЕРАЦИИ",
            font=FONTS['h2'],
            bg=COLORS['card'],
            fg=COLORS['primary'],
            padx=20,
            pady=15
        ).pack(anchor="w")

        history_content = tk.Frame(history_card, bg=COLORS['card'], padx=20)
        history_content.pack(fill="both", expand=True, pady=(0, 20))

        columns = ("Время", "Действие", "Пароль", "Оценка", "Энтропия", "Утечки", "Кол-во")
        self.history_tree = ttk.Treeview(history_content, columns=columns, show="headings", height=12)

        col_widths = [120, 80, 100, 70, 70, 70, 70]
        for col, width in zip(columns, col_widths):
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=width, anchor='center')

        scrollbar = ttk.Scrollbar(history_content, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)

        self.history_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        history_buttons = tk.Frame(history_content, bg=COLORS['card'])
        history_buttons.pack(fill="x", pady=(10, 0))

        ModernButton(history_buttons,
            text="🔄 Обновить",
            bg=COLORS['secondary'],
            command=self.update_stats_display,
            padx=10
        ).pack(side="left", padx=5)

        ModernButton(history_buttons,
            text="🗑️ Очистить историю",
            bg=COLORS['danger'],
            command=self.clear_history,
            padx=10
        ).pack(side="left", padx=5)

        ModernButton(history_buttons,
            text="💾 Экспорт в файл",
            bg=COLORS['info'],
            command=self.export_history,
            padx=10
        ).pack(side="left", padx=5)

        self.update_history_table()

    def setup_status_bar(self):
        status_bar = tk.Frame(self.window, bg=COLORS['primary'], height=30)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)

        self.status_label = tk.Label(status_bar,
            text="Готов к работе",
            font=FONTS['small'],
            bg=COLORS['primary'],
            fg=COLORS['light']
        )
        self.status_label.pack(side="left", padx=15)

        version_label = tk.Label(status_bar,
            text="Версия 4.0 | Учебный проект для олимпиады",
            font=FONTS['small'],
            bg=COLORS['primary'],
            fg=COLORS['light']
        )
        version_label.pack(side="right", padx=15)

    def update_stats_display_init(self):
        stats = self.analyzer.get_stats()

        for widget in self.stats_grid.winfo_children():
            widget.destroy()

        stat_items = [
            ("📊 Всего проверок", f"{stats['total_checks']}", COLORS['secondary']),
            ("⚡ Проверок сегодня", f"{stats['checks_today']}", COLORS['success']),
            ("🏆 Лучшая оценка", f"{stats['best_strength']}/5", COLORS['success']),
            ("⚠️ Утечек найдено", f"{stats['leaks_found']}", COLORS['danger']),
            ("📈 Средняя оценка", f"{stats['avg_strength']}/5", COLORS['warning']),
            ("🔢 Сгенерировано", f"{stats['total_generated']}", COLORS['info'])
        ]

        for i, (title, value, color) in enumerate(stat_items):
            card = tk.Frame(self.stats_grid, bg=COLORS['light'], relief=tk.RAISED, bd=1)
            card.grid(row=i//3, column=i%3, padx=5, pady=5, sticky="nsew")

            self.stats_grid.columnconfigure(i%3, weight=1)
            self.stats_grid.rowconfigure(i//3, weight=1)

            tk.Label(card,
                text=title,
                font=FONTS['small'],
                bg=COLORS['light'],
                fg=COLORS['dark']
            ).pack(pady=(10, 5))

            tk.Label(card,
                text=value,
                font=("Segoe UI", 16, "bold"),
                bg=COLORS['light'],
                fg=color
            ).pack(pady=(0, 10))

    def update_gen_settings(self):
        for frame in [self.random_frame, self.passphrase_frame, self.pattern_frame]:
            if frame.winfo_ismapped():
                frame.pack_forget()

        if self.gen_type.get() == "random":
            self.random_frame.pack(fill="x", pady=(10, 0))
        elif self.gen_type.get() == "passphrase":
            self.passphrase_frame.pack(fill="x", pady=(10, 0))
        elif self.gen_type.get() == "pattern":
            self.pattern_frame.pack(fill="x", pady=(10, 0))

    def generate_password(self):
        gen_type = self.gen_type.get()

        try:
            if gen_type == "random":
                password = self.generator.generate_random(
                    length=self.random_length.get(),
                    use_letters=self.use_upper.get(),
                    use_digits=self.use_digits.get(),
                    use_special=self.use_special.get()
                )
            elif gen_type == "passphrase":
                password = self.generator.generate_passphrase(
                    word_count=self.phrase_words.get(),
                    separator=self.phrase_separator.get(),
                    capitalize=self.phrase_capitalize.get(),
                    add_number=self.phrase_add_number.get()
                )
            elif gen_type == "pattern":
                password = self.generator.generate_pattern(
                    pattern=self.pattern_text.get()
                )

            self.generated_password_var.set(password)
            self.generated_entry.config(fg=COLORS['primary'])

            entropy = self.analyzer.calculate_entropy(password)
            strength, score, _ = self.analyzer.check_strength(password)
            self.analyzer.save_to_history(password, score, action="generate")

            self.gen_stats_label.config(
                text=f"Сгенерировано паролей: {self.generator.stats['total_generated']}"
            )

            self.show_status(f"Сгенерирован новый пароль (энтропия: {entropy} бит)", "success")

            self.update_stats_display()

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать пароль: {str(e)}")

    def copy_generated(self):
        password = self.generated_password_var.get()
        if password:
            self.window.clipboard_clear()
            self.window.clipboard_append(password)
            self.show_status("Пароль скопирован в буфер обмена", "success")
            self.generated_entry.config(bg='#d4edda')
            self.window.after(500, lambda: self.generated_entry.config(bg='white'))

    def check_generated_password(self):
        password = self.generated_password_var.get()
        if password:
            self.password_var.set(password)
            self.notebook.select(0)
            self.real_time_check()

    def update_stats_display(self):
        stats = self.analyzer.get_stats()

        for widget in self.stats_grid.winfo_children():
            widget.destroy()

        stat_items = [
            ("📊 Всего проверок", f"{stats['total_checks']}", COLORS['secondary']),
            ("⚡ Проверок сегодня", f"{stats['checks_today']}", COLORS['success']),
            ("🏆 Лучшая оценка", f"{stats['best_strength']}/5", COLORS['success']),
            ("⚠️ Утечек найдено", f"{stats['leaks_found']}", COLORS['danger']),
            ("📈 Средняя оценка", f"{stats['avg_strength']}/5", COLORS['warning']),
            ("🔢 Сгенерировано", f"{stats['total_generated']}", COLORS['info'])
        ]

        for i, (title, value, color) in enumerate(stat_items):
            card = tk.Frame(self.stats_grid, bg=COLORS['light'], relief=tk.RAISED, bd=1)
            card.grid(row=i//3, column=i%3, padx=5, pady=5, sticky="nsew")

            self.stats_grid.columnconfigure(i%3, weight=1)
            self.stats_grid.rowconfigure(i//3, weight=1)

            tk.Label(card,
                text=title,
                font=FONTS['small'],
                bg=COLORS['light'],
                fg=COLORS['dark']
            ).pack(pady=(10, 5))

            tk.Label(card,
                text=value,
                font=("Segoe UI", 16, "bold"),
                bg=COLORS['light'],
                fg=color
            ).pack(pady=(0, 10))

        self.update_history_table()

    def update_history_table(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        columns = ("Время", "Действие", "Пароль", "Оценка", "Энтропия", "Утечки", "Кол-во")
        self.history_tree.configure(columns=columns)

        col_widths = [120, 80, 100, 70, 70, 70, 70]
        for col, width in zip(columns, col_widths):
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=width, anchor='center')

        for entry in reversed(self.analyzer.history[-50:]):
            action_icon = "🔍" if entry.get('action', 'check') == 'check' else "⚡"
            action_text = "Проверка" if entry.get('action', 'check') == 'check' else "Генерация"

            leaks_icon = "✅"
            leaks_count = ""
            if entry.get('leaks_found', False):
                pwned_count = entry.get('pwned_count', 0)
                if pwned_count > 0:
                    leaks_icon = f"⚠️ ({pwned_count})"
                    leaks_count = pwned_count
                else:
                    leaks_icon = "⚠️"

            self.history_tree.insert("", 0, values=(
                entry.get('timestamp', '')[11:16],
                f"{action_icon} {action_text}",
                entry.get('password_preview', '***'),
                f"{entry.get('strength_score', 0)}/5",
                f"{entry.get('entropy', 0)}",
                leaks_icon,
                leaks_count
            ))

    def clear_history(self):
        if messagebox.askyesno("Подтверждение", "Вы действительно хотите очистить всю историю?\nЭто действие нельзя отменить."):
            self.analyzer.history = []
            try:
                with open(self.analyzer.history_file, 'w', encoding='utf-8') as f:
                    json.dump([], f)
            except:
                pass
            self.update_stats_display()
            self.show_status("История очищена", "warning")

    def export_history(self):
        try:
            filename = f"password_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ИСТОРИЯ ПРОВЕРОК И ГЕНЕРАЦИИ ПАРОЛЕЙ\n")
                f.write("=" * 50 + "\n\n")

                for entry in self.analyzer.history:
                    f.write(f"Время: {entry.get('timestamp', '')}\n")
                    f.write(f"Действие: {entry.get('action', 'check')}\n")
                    f.write(f"Пароль: {'*' * len(entry.get('password_preview', '***'))}\n")
                    f.write(f"Оценка: {entry.get('strength_score', 0)}/5\n")
                    f.write(f"Энтропия: {entry.get('entropy', 0)} бит\n")
                    f.write(f"Утечки: {'Да' if entry.get('leaks_found', False) else 'Нет'}")
                    if entry.get('leaks_found', False):
                        f.write(f" ({entry.get('pwned_count', 0)} раз)\n")
                    else:
                        f.write("\n")
                    f.write("-" * 30 + "\n")

            self.show_status(f"История экспортирована в {filename}", "success")
            messagebox.showinfo("Успех", f"История успешно экспортирована в файл:\n{filename}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать историю: {str(e)}")

    def show_status(self, message, status_type="info"):
        colors = {
            "success": ("#d4edda", "#155724"),
            "error": ("#f8d7da", "#721c24"),
            "warning": ("#fff3cd", "#856404"),
            "info": ("#d1ecf1", "#0c5460")
        }

        bg, fg = colors.get(status_type, colors["info"])
        self.status_label.config(text=message, bg=bg, fg=fg)
        self.window.after(3000, lambda: self.status_label.config(
            text="Готов к работе",
            bg=COLORS['primary'],
            fg=COLORS['light']
        ))

    def real_time_check(self):
        password = self.password_var.get()

        if not password:
            self.strength_label.config(text="Введите пароль", fg=COLORS['dark'])
            self.time_label.config(text="")
            self.strength_progress['value'] = 0
            self.entropy_value_label.config(text="0.0")
            self.entropy_level_label.config(text="Нет данных")
            self.entropy_scale_label.config(text="")
            self.analysis_text.config(state=tk.NORMAL)
            self.analysis_text.delete(1.0, tk.END)
            self.analysis_text.insert(1.0, "Введите пароль для анализа")
            self.analysis_text.config(state=tk.DISABLED)
            return

        strength, score, time = self.analyzer.check_strength(password)

        strength_colors = {
            1: COLORS['danger'], 2: '#ff6b6b',
            3: COLORS['warning'], 4: '#1dd1a1', 5: COLORS['success']
        }
        color = strength_colors.get(score, COLORS['dark'])

        self.strength_label.config(text=strength.upper(), fg=color)
        self.time_label.config(text=f"Время взлома: {time}")
        self.strength_progress['value'] = score

        entropy = self.analyzer.calculate_entropy(password)
        entropy_level, entropy_color, _ = self.analyzer.get_entropy_level(entropy)

        self.entropy_value_label.config(text=f"{entropy}", fg=entropy_color)
        self.entropy_level_label.config(text=entropy_level, fg=entropy_color)

        scale_text = self.create_entropy_scale(entropy)
        self.entropy_scale_label.config(text=scale_text)

        assessment, color, tips, warnings, recommendations, entropy_val, entropy_lvl = \
            self.analyzer.detailed_analysis(password)

        self.analysis_text.config(state=tk.NORMAL)
        self.analysis_text.delete(1.0, tk.END)

        analysis_output = f"📊 ДЕТАЛЬНЫЙ АНАЛИЗ\n{'='*40}\n\n"
        analysis_output += f"Энтропия: {entropy_val} бит ({entropy_lvl})\n\n"

        if tips:
            analysis_output += "✅ ХОРОШО:\n"
            for tip in tips:
                analysis_output += f"  • {tip}\n"
            analysis_output += "\n"

        if warnings:
            analysis_output += "⚠️  ПРОБЛЕМЫ:\n"
            for warning in warnings:
                analysis_output += f"  • {warning}\n"
            analysis_output += "\n"

        if recommendations:
            analysis_output += "💡 РЕКОМЕНДАЦИИ:\n"
            for rec in recommendations:
                analysis_output += f"  • {rec}\n"

        self.analysis_text.insert(1.0, analysis_output)
        self.analysis_text.config(state=tk.DISABLED)

        self.analyzer.save_to_history(password, score, action="check")

        if self.notebook.index(self.notebook.select()) == 2:
            self.update_stats_display()

    def create_entropy_scale(self, entropy):
        scale = ""
        levels = [
            (0, 28, "█", "#e74c3c"),
            (28, 36, "█", "#ff6b6b"),
            (36, 60, "█", "#f39c12"),
            (60, 80, "█", "#1dd1a1"),
            (80, 120, "█", "#2ecc71")
        ]

        for start, end, char, color in levels:
            if entropy >= end:
                scale += char * 3 + " "
            elif entropy > start:
                percent = (entropy - start) / (end - start)
                filled = int(3 * percent)
                scale += char * filled + "░" * (3 - filled) + " "
            else:
                scale += "░░░ "

        return f"[{scale.strip()}] {entropy} бит"

    def toggle_password(self):
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def clear_password(self):
        self.password_var.set("")
        self.password_entry.focus()

    def check_pwned(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Внимание", "Сначала введите пароль для проверки.")
            return

        self.pwned_result.config(text="⏳ Проверяем наличие в утечках...", fg=COLORS['info'])
        self.window.update()

        try:
            count = self.analyzer.check_pwned_api(password)
        except Exception as e:
            self.pwned_result.config(
                text=f"❌ Ошибка при проверке: {str(e)}",
                fg=COLORS['warning']
            )
            return

        if count == -1:
            self.pwned_result.config(
                text="❌ Ошибка сети. Проверьте подключение к интернету.",
                fg=COLORS['warning']
            )
        elif count > 0:
            formatted_count = f"{count:,}".replace(",", " ")
            self.pwned_result.config(
                text=f"⚠️  ВНИМАНИЕ! Этот пароль найден в {formatted_count} утечках данных!\nРекомендуем немедленно изменить его во всех сервисах.",
                fg=COLORS['danger']
            )

            updated = False
            for entry in self.analyzer.history:
                preview = password[:2] + "***" + password[-1:] if len(password) > 3 else "***"
                if entry.get('password_preview', '') == preview:
                    entry['leaks_found'] = True
                    entry['pwned_count'] = count
                    updated = True
                    break

            if not updated:
                entropy = self.analyzer.calculate_entropy(password)
                strength, score, _ = self.analyzer.check_strength(password)
                self.analyzer.save_to_history(password, score, leaks_found=True, pwned_count=count)

            self.analyzer.save_history()

        else:
            self.pwned_result.config(
                text="✅ Этот пароль не найден в известных утечках данных.",
                fg=COLORS['success']
            )

            updated = False
            for entry in self.analyzer.history:
                preview = password[:2] + "***" + password[-1:] if len(password) > 3 else "***"
                if entry.get('password_preview', '') == preview:
                    entry['leaks_found'] = False
                    entry['pwned_count'] = 0
                    updated = True
                    break

            if not updated:
                entropy = self.analyzer.calculate_entropy(password)
                strength, score, _ = self.analyzer.check_strength(password)
                self.analyzer.save_to_history(password, score, leaks_found=False, pwned_count=0)

            self.analyzer.save_history()

        if hasattr(self, 'stats_grid'):
            self.update_stats_display()

        self.show_status("Проверка утечек завершена", "info")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PasswordApp()
    app.run()