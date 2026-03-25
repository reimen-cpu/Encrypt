"""
Cifrador/Descifrador de Texto Avanzado
Algoritmos: AES-256-GCM | Fernet
Requiere: pip install cryptography
"""

import os
import json
import base64
import tkinter as tk
from tkinter import ttk, messagebox

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ─────────────────────────────────────────────
#  Lógica de Cifrado
# ─────────────────────────────────────────────

def _derive_key_scrypt(password: str, salt: bytes) -> bytes:
    """Deriva una clave AES-256 usando Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def aes_gcm_encrypt(plaintext: str, password: str) -> str:
    salt  = os.urandom(16)
    nonce = os.urandom(12)
    key   = _derive_key_scrypt(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = {
        "salt":       base64.b64encode(salt).decode(),
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def aes_gcm_decrypt(token: str, password: str) -> str:
    try:
        payload    = json.loads(base64.b64decode(token.encode()))
        salt       = base64.b64decode(payload["salt"])
        nonce      = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
    except Exception:
        raise ValueError("El token está corrupto o tiene un formato inválido.")
    key = _derive_key_scrypt(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Contraseña incorrecta o datos corruptos (AES-GCM).")
    return plaintext.decode("utf-8")


def _fernet_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def fernet_encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(16)
    key  = _fernet_key_from_password(password, salt)
    f    = Fernet(key)
    token = f.encrypt(plaintext.encode("utf-8"))
    payload = {
        "salt":  base64.b64encode(salt).decode(),
        "token": token.decode(),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def fernet_decrypt(data: str, password: str) -> str:
    try:
        payload = json.loads(base64.b64decode(data.encode()))
        salt    = base64.b64decode(payload["salt"])
        token   = payload["token"].encode()
    except Exception:
        raise ValueError("El token está corrupto o tiene un formato inválido.")
    key = _fernet_key_from_password(password, salt)
    f   = Fernet(key)
    try:
        plaintext = f.decrypt(token)
    except InvalidToken:
        raise ValueError("Contraseña incorrecta o datos corruptos (Fernet).")
    return plaintext.decode("utf-8")


# ─────────────────────────────────────────────
#  Paleta de colores
# ─────────────────────────────────────────────
C = {
    "bg":          "#1a1d23",
    "surface":     "#22262f",
    "surface2":    "#2b303c",
    "border":      "#3a3f4d",
    "accent":      "#4f8ef7",
    "accent_dark": "#3a6fd8",
    "success":     "#3ecf8e",
    "danger":      "#f75f5f",
    "text":        "#e8eaf0",
    "text_dim":    "#8891a8",
    "text_muted":  "#555d72",
}


# ─────────────────────────────────────────────
#  Aplicación
# ─────────────────────────────────────────────

class CifradorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cifrador / Descifrador Avanzado")
        self.geometry("680x620")
        self.minsize(580, 560)
        self.configure(bg=C["bg"])
        self.resizable(True, True)

        self._build_style()
        self._build_ui()

    # ── Estilo ttk ──────────────────────────────
    def _build_style(self):
        st = ttk.Style(self)
        st.theme_use("clam")

        # Frame / Label
        st.configure("TFrame",       background=C["bg"])
        st.configure("Surface.TFrame", background=C["surface"])
        st.configure("TLabel",
                     background=C["bg"],
                     foreground=C["text"],
                     font=("Segoe UI", 10))
        st.configure("Dim.TLabel",
                     background=C["bg"],
                     foreground=C["text_dim"],
                     font=("Segoe UI", 9))
        st.configure("Header.TLabel",
                     background=C["bg"],
                     foreground=C["text"],
                     font=("Segoe UI", 13, "bold"))
        st.configure("Title.TLabel",
                     background=C["bg"],
                     foreground=C["accent"],
                     font=("Segoe UI", 17, "bold"))

        # Combobox
        st.configure("TCombobox",
                     fieldbackground=C["surface2"],
                     background=C["surface2"],
                     foreground=C["text"],
                     selectbackground=C["accent"],
                     selectforeground=C["text"],
                     bordercolor=C["border"],
                     arrowcolor=C["text_dim"],
                     font=("Segoe UI", 10))
        st.map("TCombobox",
               fieldbackground=[("readonly", C["surface2"])],
               foreground=[("readonly", C["text"])])

        # Separator
        st.configure("TSeparator", background=C["border"])

        # Scrollbar
        st.configure("Vertical.TScrollbar",
                     background=C["surface2"],
                     troughcolor=C["surface"],
                     bordercolor=C["surface"],
                     arrowcolor=C["text_dim"],
                     relief="flat")

    # ── Layout principal ─────────────────────────
    def _build_ui(self):
        pad = {"padx": 24, "pady": 0}

        # ── Header ──
        hdr = ttk.Frame(self, style="TFrame")
        hdr.pack(fill="x", padx=0, pady=0)
        hdr.configure(style="TFrame")

        top_bar = tk.Frame(hdr, bg=C["surface"], height=56)
        top_bar.pack(fill="x")
        top_bar.pack_propagate(False)

        icon_lbl = tk.Label(top_bar, text="🔐", font=("Segoe UI", 18),
                            bg=C["surface"], fg=C["accent"])
        icon_lbl.pack(side="left", padx=(20, 6), pady=12)

        title_lbl = tk.Label(top_bar, text="Cifrador Avanzado",
                             font=("Segoe UI", 14, "bold"),
                             bg=C["surface"], fg=C["text"])
        title_lbl.pack(side="left", pady=12)

        sub_lbl = tk.Label(top_bar, text="AES-256-GCM  ·  Fernet",
                           font=("Segoe UI", 9),
                           bg=C["surface"], fg=C["text_muted"])
        sub_lbl.pack(side="right", padx=20, pady=12)

        # ── Body ──
        body = ttk.Frame(self, style="TFrame")
        body.pack(fill="both", expand=True, padx=24, pady=16)

        # Fila 1: Algoritmo
        row_algo = ttk.Frame(body, style="TFrame")
        row_algo.pack(fill="x", pady=(0, 12))

        ttk.Label(row_algo, text="Algoritmo", style="Dim.TLabel").pack(
            anchor="w", pady=(0, 4))

        self.algo_var = tk.StringVar(value="AES-256-GCM")
        algo_cb = ttk.Combobox(row_algo, textvariable=self.algo_var,
                               values=["AES-256-GCM", "Fernet"],
                               state="readonly", width=22,
                               style="TCombobox")
        algo_cb.pack(anchor="w")

        # Fila 2: Contraseña
        row_pw = ttk.Frame(body, style="TFrame")
        row_pw.pack(fill="x", pady=(0, 12))

        ttk.Label(row_pw, text="Contraseña", style="Dim.TLabel").pack(
            anchor="w", pady=(0, 4))

        pw_frame = tk.Frame(row_pw, bg=C["surface2"],
                            highlightbackground=C["border"],
                            highlightthickness=1, bd=0)
        pw_frame.pack(fill="x")

        self.pw_var   = tk.StringVar()
        self.show_pw  = tk.BooleanVar(value=False)

        self.pw_entry = tk.Entry(pw_frame, textvariable=self.pw_var,
                                 show="•", font=("Segoe UI", 10),
                                 bg=C["surface2"], fg=C["text"],
                                 insertbackground=C["accent"],
                                 relief="flat", bd=8,
                                 highlightthickness=0)
        self.pw_entry.pack(side="left", fill="x", expand=True)

        toggle_btn = tk.Button(pw_frame, text="👁",
                               command=self._toggle_pw,
                               bg=C["surface2"], fg=C["text_dim"],
                               activebackground=C["surface2"],
                               activeforeground=C["text"],
                               relief="flat", bd=0,
                               cursor="hand2", font=("Segoe UI", 11),
                               padx=8)
        toggle_btn.pack(side="right")

        # Fila 3: Texto entrada
        row_in = ttk.Frame(body, style="TFrame")
        row_in.pack(fill="both", expand=True, pady=(0, 8))

        ttk.Label(row_in, text="Texto de entrada", style="Dim.TLabel").pack(
            anchor="w", pady=(0, 4))

        in_frame = tk.Frame(row_in, bg=C["surface2"],
                            highlightbackground=C["border"],
                            highlightthickness=1)
        in_frame.pack(fill="both", expand=True)

        self.input_text = tk.Text(in_frame, height=6,
                                  font=("Consolas", 10),
                                  bg=C["surface2"], fg=C["text"],
                                  insertbackground=C["accent"],
                                  selectbackground=C["accent"],
                                  relief="flat", bd=8, wrap="word",
                                  highlightthickness=0)
        in_sb = ttk.Scrollbar(in_frame, orient="vertical",
                              command=self.input_text.yview)
        self.input_text.configure(yscrollcommand=in_sb.set)
        in_sb.pack(side="right", fill="y")
        self.input_text.pack(fill="both", expand=True)

        # Fila 4: Botones
        row_btns = ttk.Frame(body, style="TFrame")
        row_btns.pack(fill="x", pady=(0, 8))

        self._btn(row_btns, "  🔒  Cifrar  ", self._encrypt,
                  C["accent"], C["accent_dark"]).pack(
            side="left", padx=(0, 10), ipady=6, ipadx=4)

        self._btn(row_btns, "  🔓  Descifrar  ", self._decrypt,
                  C["surface2"], C["border"],
                  fg=C["text"]).pack(
            side="left", ipady=6, ipadx=4)

        clear_btn = tk.Button(row_btns, text="✕ Limpiar",
                              command=self._clear,
                              bg=C["bg"], fg=C["text_muted"],
                              activebackground=C["bg"],
                              activeforeground=C["text_dim"],
                              relief="flat", bd=0,
                              font=("Segoe UI", 9),
                              cursor="hand2")
        clear_btn.pack(side="right")

        # Fila 5: Texto salida
        row_out = ttk.Frame(body, style="TFrame")
        row_out.pack(fill="both", expand=True, pady=(0, 0))

        out_header = ttk.Frame(row_out, style="TFrame")
        out_header.pack(fill="x")
        ttk.Label(out_header, text="Resultado", style="Dim.TLabel").pack(
            side="left", pady=(0, 4))

        copy_btn = tk.Button(out_header, text="⎘ Copiar",
                             command=self._copy_output,
                             bg=C["bg"], fg=C["accent"],
                             activebackground=C["bg"],
                             activeforeground=C["accent_dark"],
                             relief="flat", bd=0,
                             font=("Segoe UI", 9),
                             cursor="hand2")
        copy_btn.pack(side="right", pady=(0, 4))

        out_frame = tk.Frame(row_out, bg=C["surface"],
                             highlightbackground=C["border"],
                             highlightthickness=1)
        out_frame.pack(fill="both", expand=True)

        self.output_text = tk.Text(out_frame, height=6,
                                   font=("Consolas", 10),
                                   bg=C["surface"], fg=C["success"],
                                   insertbackground=C["success"],
                                   selectbackground=C["accent"],
                                   relief="flat", bd=8, wrap="word",
                                   state="disabled",
                                   highlightthickness=0)
        out_sb = ttk.Scrollbar(out_frame, orient="vertical",
                               command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=out_sb.set)
        out_sb.pack(side="right", fill="y")
        self.output_text.pack(fill="both", expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Listo · Ninguna operación realizada")
        status_bar = tk.Label(self, textvariable=self.status_var,
                              bg=C["surface"], fg=C["text_muted"],
                              font=("Segoe UI", 8), anchor="w",
                              padx=24, pady=5)
        status_bar.pack(fill="x", side="bottom")

    # ── Helpers UI ───────────────────────────────
    def _btn(self, parent, text, cmd, bg, active_bg, fg=C["text"]):
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg,
                         activebackground=active_bg,
                         activeforeground=fg,
                         relief="flat", bd=0,
                         font=("Segoe UI", 10, "bold"),
                         cursor="hand2")

    def _toggle_pw(self):
        current = self.pw_entry.cget("show")
        self.pw_entry.config(show="" if current == "•" else "•")

    def _set_output(self, text: str, color: str = None):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        if color:
            self.output_text.config(fg=color)
        self.output_text.config(state="disabled")

    def _copy_output(self):
        content = self.output_text.get("1.0", "end").strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self.status_var.set("✓ Resultado copiado al portapapeles")

    def _clear(self):
        self.input_text.delete("1.0", "end")
        self._set_output("")
        self.pw_var.set("")
        self.status_var.set("Campos limpiados")

    def _get_inputs(self):
        text     = self.input_text.get("1.0", "end").strip()
        password = self.pw_var.get().strip()
        algo     = self.algo_var.get()

        if not text:
            messagebox.showwarning("Campo vacío",
                                   "Por favor ingresa el texto de entrada.")
            return None, None, None
        if not password:
            messagebox.showwarning("Campo vacío",
                                   "Por favor ingresa una contraseña.")
            return None, None, None
        return text, password, algo

    # ── Operaciones ──────────────────────────────
    def _encrypt(self):
        text, password, algo = self._get_inputs()
        if text is None:
            return
        try:
            if algo == "AES-256-GCM":
                result = aes_gcm_encrypt(text, password)
            else:
                result = fernet_encrypt(text, password)
            self._set_output(result, C["success"])
            self.status_var.set(
                f"✓ Texto cifrado correctamente · Algoritmo: {algo}")
        except Exception as e:
            messagebox.showerror("Error al cifrar", str(e))
            self.status_var.set("✗ Error durante el cifrado")

    def _decrypt(self):
        text, password, algo = self._get_inputs()
        if text is None:
            return
        try:
            if algo == "AES-256-GCM":
                result = aes_gcm_decrypt(text, password)
            else:
                result = fernet_decrypt(text, password)
            self._set_output(result, C["text"])
            self.status_var.set(
                f"✓ Texto descifrado correctamente · Algoritmo: {algo}")
        except ValueError as e:
            messagebox.showerror("Error al descifrar", str(e))
            self._set_output("", C["danger"])
            self.status_var.set("✗ Descifrado fallido · Verifica contraseña y datos")
        except Exception as e:
            messagebox.showerror("Error inesperado", str(e))
            self.status_var.set("✗ Error inesperado")


# ─────────────────────────────────────────────
#  Punto de entrada
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = CifradorApp()
    app.mainloop()
