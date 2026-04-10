"""
Encrypt.py
==========
Cifrador / Descifrador Avanzado — Sistema Criptográfico Híbrido y Post-Cuántico

Interfaz Tkinter con soporte completo para:
  • AES-256-GCM  — cifrado simétrico por contraseña (Scrypt)
  • Fernet       — cifrado simétrico por contraseña (PBKDF2)
  • ML-KEM-768   — cifrado híbrido post-cuántico (NIST FIPS 203)
  • HQC-KEM      — cifrado híbrido PQC (condicional)
  • ML-DSA       — firma digital post-cuántica (NIST FIPS 204)
  • SLH-DSA      — firma digital PQC conservadora (NIST FIPS 205)
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox

# ─────────────────────────────────────────────────────────────────────────────
#  sys.path para importar módulos del mismo directorio
# ─────────────────────────────────────────────────────────────────────────────
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s %(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

from crypto_classic import (
    aes_gcm_encrypt, aes_gcm_decrypt,
    fernet_encrypt,  fernet_decrypt,
)
from liboqs_runtime import (
    OQS_AVAILABLE, check_liboqs_runtime,
    get_available_kems, get_available_sigs,
)

_PQC_LOAD_OK, _PQC_VERSION, _PQC_ERROR = check_liboqs_runtime()

if _PQC_LOAD_OK:
    from crypto_core.kem import kem_encrypt, kem_decrypt
    from crypto_core.dsa import dsa_sign, dsa_verify
    from key_management.key_manager import generate_kem_keypair, generate_sig_keypair

# ─────────────────────────────────────────────────────────────────────────────
#  Listas de algoritmos disponibles
# ─────────────────────────────────────────────────────────────────────────────
_CLASSIC_ALGOS = ["AES-256-GCM", "Fernet"]
_KEM_ALGOS_RAW = get_available_kems() if _PQC_LOAD_OK else []
_SIG_ALGOS_RAW = get_available_sigs() if _PQC_LOAD_OK else []

# Nombres de display con etiqueta de categoría
_KEM_DISPLAY  = {f"{k}  [KEM]": k for k in _KEM_ALGOS_RAW}
_SIG_DISPLAY  = {f"{s}  [DSA]": s for s in _SIG_ALGOS_RAW}
_ALL_ALGOS    = _CLASSIC_ALGOS + list(_KEM_DISPLAY) + list(_SIG_DISPLAY)

def _is_kem(display: str) -> bool:
    return display in _KEM_DISPLAY

def _is_dsa(display: str) -> bool:
    return display in _SIG_DISPLAY

def _base(display: str) -> str:
    return (_KEM_DISPLAY.get(display) or _SIG_DISPLAY.get(display) or display)

# ─────────────────────────────────────────────────────────────────────────────
#  Sistema de colores
# ─────────────────────────────────────────────────────────────────────────────
C = {
    "bg":           "#0f1117",
    "bg2":          "#161b27",
    "surface":      "#1c2333",
    "surface2":     "#232b3e",
    "surface3":     "#2a3450",
    "border":       "#2e3a52",
    "border2":      "#3d4f70",
    "accent":       "#4d8ef0",
    "accent2":      "#2563eb",
    "accent_glow":  "#1d4ed8",
    "success":      "#22c55e",
    "success2":     "#15803d",
    "danger":       "#ef4444",
    "danger2":      "#991b1b",
    "warning":      "#f59e0b",
    "pqc":          "#a855f7",
    "pqc2":         "#7c3aed",
    "pqc_dim":      "#6d28d9",
    "text":         "#e2e8f0",
    "text_dim":     "#94a3b8",
    "text_muted":   "#4b5a72",
    "text_subtle":  "#334155",
}

# ─────────────────────────────────────────────────────────────────────────────
#  Aplicación
# ─────────────────────────────────────────────────────────────────────────────
class CifradorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cifrador / Descifrador Avanzado")
        self.geometry("780x780")
        self.minsize(660, 680)
        self.configure(bg=C["bg"])
        self.resizable(True, True)

        self._pqc_pub_key  = ""
        self._pqc_priv_key = ""

        self._build_style()
        self._build_ui()
        self._on_algo_change()

        if not _PQC_LOAD_OK and _PQC_ERROR:
            self.after(600, lambda: self._show_pqc_warning())

    # ── Estilos ttk ──────────────────────────────────────────────────────────
    def _build_style(self):
        st = ttk.Style(self)
        st.theme_use("clam")

        st.configure("TFrame",           background=C["bg"])
        st.configure("Card.TFrame",       background=C["surface"])
        st.configure("TLabel",
                     background=C["bg"], foreground=C["text"],
                     font=("Segoe UI", 10))
        st.configure("Dim.TLabel",
                     background=C["bg"], foreground=C["text_dim"],
                     font=("Segoe UI", 9))
        st.configure("Caption.TLabel",
                     background=C["surface"], foreground=C["text_dim"],
                     font=("Segoe UI", 8))
        st.configure("CardTitle.TLabel",
                     background=C["surface"], foreground=C["text"],
                     font=("Segoe UI", 9, "bold"))
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
        st.configure("TSeparator", background=C["border"])
        st.configure("Vertical.TScrollbar",
                     background=C["surface2"],
                     troughcolor=C["surface"],
                     bordercolor=C["surface"],
                     arrowcolor=C["text_dim"],
                     relief="flat")
        st.configure("TProgressbar",
                     background=C["accent"],
                     troughcolor=C["surface2"])

    # ── UI principal ──────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ──────────────────────────────────────────────────────────
        header = tk.Frame(self, bg=C["surface"], height=60)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Línea de acento superior
        tk.Frame(self, bg=C["accent"], height=2).pack(fill="x")

        left_hdr = tk.Frame(header, bg=C["surface"])
        left_hdr.pack(side="left", padx=20, pady=12)

        tk.Label(left_hdr, text="🔐", font=("Segoe UI", 20),
                 bg=C["surface"], fg=C["accent"]).pack(side="left", padx=(0,10))

        title_frm = tk.Frame(left_hdr, bg=C["surface"])
        title_frm.pack(side="left")
        tk.Label(title_frm, text="Cifrador Avanzado",
                 font=("Segoe UI", 15, "bold"),
                 bg=C["surface"], fg=C["text"]).pack(anchor="w")

        if _PQC_LOAD_OK:
            sub = f"AES · Fernet · PQC liboqs {_PQC_VERSION}"
            sfg = C["pqc"]
        else:
            sub = "AES-256-GCM · Fernet"
            sfg = C["text_muted"]
        tk.Label(title_frm, text=sub, font=("Segoe UI", 8),
                 bg=C["surface"], fg=sfg).pack(anchor="w")

        # Indicador de estado PQC (derecha del header)
        right_hdr = tk.Frame(header, bg=C["surface"])
        right_hdr.pack(side="right", padx=20, pady=12)
        if _PQC_LOAD_OK:
            self._badge("⚛ PQC activo", C["pqc"],  C["surface"], right_hdr).pack(side="right")
        else:
            self._badge("⚠ Solo clásico", C["warning"], C["surface"], right_hdr).pack(side="right")

        # ── Cuerpo con padding ───────────────────────────────────────────────
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=20, pady=16)

        # ───────────────────────────────────────────────────────────────────
        # SECCIÓN 1: Selección de algoritmo
        # ───────────────────────────────────────────────────────────────────
        algo_card = self._card(body)
        algo_card.pack(fill="x", pady=(0, 10))

        algo_inner = tk.Frame(algo_card, bg=C["surface"])
        algo_inner.pack(fill="x", padx=16, pady=12)

        # Columna izquierda: selector
        left_col = tk.Frame(algo_inner, bg=C["surface"])
        left_col.pack(side="left", fill="x", expand=True)

        tk.Label(left_col, text="A L G O R I T M O", font=("Segoe UI", 7, "bold"),
                 bg=C["surface"], fg=C["text_muted"]).pack(anchor="w")

        selector_row = tk.Frame(left_col, bg=C["surface"])
        selector_row.pack(anchor="w", pady=(4,0))

        self.algo_var = tk.StringVar(value="AES-256-GCM")
        self.algo_cb  = ttk.Combobox(selector_row,
                                     textvariable=self.algo_var,
                                     values=_ALL_ALGOS,
                                     state="readonly", width=28,
                                     style="TCombobox")
        self.algo_cb.pack(side="left")
        self.algo_cb.bind("<<ComboboxSelected>>", lambda e: self._on_algo_change())

        # Chip de tipo de algoritmo
        self.algo_chip_var = tk.StringVar()
        self.algo_chip = tk.Label(selector_row, textvariable=self.algo_chip_var,
                                  font=("Segoe UI", 8, "bold"),
                                  bg=C["text_muted"], fg=C["bg"],
                                  padx=8, pady=2)
        self.algo_chip.pack(side="left", padx=(8,0))

        # Columna derecha: info del algoritmo
        right_col = tk.Frame(algo_inner, bg=C["surface"])
        right_col.pack(side="right")
        self.algo_info_var = tk.StringVar()
        tk.Label(right_col, textvariable=self.algo_info_var,
                 font=("Segoe UI", 8), bg=C["surface"],
                 fg=C["text_dim"], justify="right",
                 wraplength=200).pack(anchor="e")

        # ───────────────────────────────────────────────────────────────────
        # SECCIÓN 2: Credenciales (contraseña o claves PQC)
        # ───────────────────────────────────────────────────────────────────
        self.creds_card = self._card(body)
        self.creds_card.pack(fill="x", pady=(0, 10))

        # ── Panel contraseña (clásico) ──
        self.pw_panel = tk.Frame(self.creds_card, bg=C["surface"])
        self.pw_panel.pack(fill="x", padx=16, pady=12)

        pw_hdr = tk.Frame(self.pw_panel, bg=C["surface"])
        pw_hdr.pack(fill="x", pady=(0,6))
        tk.Label(pw_hdr, text="CONTRASEÑA", font=("Segoe UI", 7, "bold"),
                 bg=C["surface"], fg=C["text_muted"]).pack(side="left")

        pw_input_frame = tk.Frame(self.pw_panel,
                                  bg=C["surface2"],
                                  highlightbackground=C["border"],
                                  highlightthickness=1)
        pw_input_frame.pack(fill="x")

        self.pw_var   = tk.StringVar()
        self.pw_entry = tk.Entry(pw_input_frame, textvariable=self.pw_var,
                                 show="•", font=("Segoe UI", 10),
                                 bg=C["surface2"], fg=C["text"],
                                 insertbackground=C["accent"],
                                 relief="flat", bd=10,
                                 highlightthickness=0)
        self.pw_entry.pack(side="left", fill="x", expand=True)

        self._icon_btn(pw_input_frame, "🎲", self._generate_password,
                       C["surface2"], C["pqc"], 12).pack(side="right", padx=2)
        self._icon_btn(pw_input_frame, "📋", self._paste_pw,
                       C["surface2"]).pack(side="right", padx=2)
        self._icon_btn(pw_input_frame, "👁", self._toggle_pw,
                       C["surface2"]).pack(side="right", padx=2)

        # Barra de fuerza de contraseña
        pw_strength_row = tk.Frame(self.pw_panel, bg=C["surface"])
        pw_strength_row.pack(fill="x", pady=(4,0))
        self.pw_strength_var = tk.StringVar(value="")
        tk.Label(pw_strength_row, textvariable=self.pw_strength_var,
                 font=("Segoe UI", 7), bg=C["surface"],
                 fg=C["text_muted"]).pack(side="left")
        self.pw_var.trace_add("write", self._update_pw_strength)

        # ── Panel de claves PQC ──
        self.pqc_panel = tk.Frame(self.creds_card, bg=C["surface"])
        # (se empaqueta condicionalmente en _on_algo_change)

        pqc_hdr_row = tk.Frame(self.pqc_panel, bg=C["surface"])
        pqc_hdr_row.pack(fill="x", padx=16, pady=(12,6))

        self.pqc_mode_label = tk.Label(pqc_hdr_row,
                                       text="⚛ CLAVES POST-CUÁNTICAS",
                                       font=("Segoe UI", 7, "bold"),
                                       bg=C["surface"], fg=C["pqc"])
        self.pqc_mode_label.pack(side="left")

        self._action_btn(pqc_hdr_row, "⚙ Generar Par de Claves",
                         self._generate_pqc_keypair,
                         C["pqc2"], C["pqc"]).pack(side="right")

        # Clave pública
        pub_section = tk.Frame(self.pqc_panel, bg=C["surface"])
        pub_section.pack(fill="x", padx=16, pady=(0,8))

        pub_lbl_row = tk.Frame(pub_section, bg=C["surface"])
        pub_lbl_row.pack(fill="x", pady=(0,3))
        tk.Label(pub_lbl_row, text="Clave Pública",
                 font=("Segoe UI", 8, "bold"),
                 bg=C["surface"], fg=C["success"]).pack(side="left")
        tk.Label(pub_lbl_row, text="para cifrar / verificar",
                 font=("Segoe UI", 7),
                 bg=C["surface"], fg=C["text_muted"]).pack(side="left", padx=(6,0))
        self._icon_btn(pub_lbl_row, "⎘", self._copy_pub_key,
                       C["surface"], C["success"], 8).pack(side="right")

        pub_frame = tk.Frame(pub_section, bg=C["surface2"],
                             highlightbackground=C["border"], highlightthickness=1)
        pub_frame.pack(fill="x")
        self.pub_key_var = tk.StringVar()
        self.pub_entry = tk.Entry(pub_frame, textvariable=self.pub_key_var,
                                  font=("Consolas", 8),
                                  bg=C["surface2"], fg=C["success"],
                                  insertbackground=C["success"],
                                  relief="flat", bd=8,
                                  highlightthickness=0)
        self.pub_entry.pack(side="left", fill="x", expand=True)
        self._icon_btn(pub_frame, "📋", self._paste_pub_key,
                       C["surface2"], C["text_dim"], 9).pack(side="right", padx=2)

        # Clave privada
        priv_section = tk.Frame(self.pqc_panel, bg=C["surface"])
        priv_section.pack(fill="x", padx=16, pady=(0,12))

        priv_lbl_row = tk.Frame(priv_section, bg=C["surface"])
        priv_lbl_row.pack(fill="x", pady=(0,3))
        tk.Label(priv_lbl_row, text="Clave Privada",
                 font=("Segoe UI", 8, "bold"),
                 bg=C["surface"], fg=C["danger"]).pack(side="left")
        tk.Label(priv_lbl_row, text="para descifrar / firmar  —  ¡mantener secreta!",
                 font=("Segoe UI", 7),
                 bg=C["surface"], fg=C["text_muted"]).pack(side="left", padx=(6,0))

        priv_frame = tk.Frame(priv_section, bg=C["surface2"],
                              highlightbackground=C["border"], highlightthickness=1)
        priv_frame.pack(fill="x")
        self.priv_key_var = tk.StringVar()
        self.priv_entry = tk.Entry(priv_frame, textvariable=self.priv_key_var,
                                   show="•", font=("Consolas", 8),
                                   bg=C["surface2"], fg=C["danger"],
                                   insertbackground=C["danger"],
                                   relief="flat", bd=8,
                                   highlightthickness=0)
        self.priv_entry.pack(side="left", fill="x", expand=True)
        self._icon_btn(priv_frame, "👁",
                       lambda: self.priv_entry.config(
                           show="" if self.priv_entry.cget("show") == "•" else "•"),
                       C["surface2"], C["text_dim"], 9).pack(side="right", padx=2)
        self._icon_btn(priv_frame, "📋", self._paste_priv_key,
                       C["surface2"], C["text_dim"], 9).pack(side="right", padx=2)

        # ───────────────────────────────────────────────────────────────────
        # SECCIÓN 3: Texto de entrada
        # ───────────────────────────────────────────────────────────────────
        input_card = self._card(body)
        input_card.pack(fill="both", expand=True, pady=(0, 10))

        in_hdr = tk.Frame(input_card, bg=C["surface"])
        in_hdr.pack(fill="x", padx=16, pady=(12,6))
        self.input_label_var = tk.StringVar(value="TEXTO DE ENTRADA")
        tk.Label(in_hdr, textvariable=self.input_label_var,
                 font=("Segoe UI", 7, "bold"),
                 bg=C["surface"], fg=C["text_muted"]).pack(side="left")

        paste_btn = self._text_btn(in_hdr, "📋 Pegar", self._paste_input,
                                   C["text_dim"])
        paste_btn.pack(side="right")
        clear_input_btn = self._text_btn(in_hdr, "✕ Borrar",
                                         lambda: self.input_text.delete("1.0","end"),
                                         C["text_muted"])
        clear_input_btn.pack(side="right", padx=(0,4))

        in_wrap = tk.Frame(input_card, bg=C["surface2"],
                           highlightbackground=C["border"], highlightthickness=1)
        in_wrap.pack(fill="both", expand=True, padx=16, pady=(0,12))

        in_sb = ttk.Scrollbar(in_wrap, orient="vertical")
        in_sb.pack(side="right", fill="y")

        self.input_text = tk.Text(in_wrap, height=6,
                                  font=("Consolas", 10),
                                  bg=C["surface2"], fg=C["text"],
                                  insertbackground=C["accent"],
                                  selectbackground=C["accent2"],
                                  selectforeground=C["text"],
                                  relief="flat", bd=10, wrap="word",
                                  highlightthickness=0,
                                  yscrollcommand=in_sb.set)
        in_sb.config(command=self.input_text.yview)
        self.input_text.pack(fill="both", expand=True)

        # ───────────────────────────────────────────────────────────────────
        # SECCIÓN 4: Campo de firma DSA (solo modo DSA)
        # ───────────────────────────────────────────────────────────────────
        self.sig_card = self._card(body)
        # se empaqueta condicionalmente

        sig_hdr = tk.Frame(self.sig_card, bg=C["surface"])
        sig_hdr.pack(fill="x", padx=16, pady=(12,6))
        tk.Label(sig_hdr, text="Paso 2: FIRMA DIGITAL (El sello o firma resultante)",
                 font=("Segoe UI", 7, "bold"),
                 bg=C["surface"], fg=C["pqc"]).pack(side="left")
        self._text_btn(sig_hdr, "⎘ Copiar",  self._copy_signature,
                       C["pqc"]).pack(side="right")
        self._text_btn(sig_hdr, "📋 Pegar",  self._paste_signature,
                       C["text_dim"]).pack(side="right", padx=(0,4))
        self._text_btn(sig_hdr, "✕ Borrar",
                       lambda: (self.sig_text.config(state="normal"),
                                self.sig_text.delete("1.0","end")),
                       C["text_muted"]).pack(side="right", padx=(0,4))

        sig_note = tk.Label(self.sig_card,
                            text="  ✍ Al firmar: El sello aparecerá aquí.   "
                                 "·   ✔ Al verificar: Pega aquí la firma a verificar.",
                            font=("Segoe UI", 7), bg=C["surface"],
                            fg=C["text_dim"], anchor="w")
        sig_note.pack(fill="x", padx=16, pady=(0,4))

        sig_wrap = tk.Frame(self.sig_card, bg=C["surface2"],
                            highlightbackground=C["border2"], highlightthickness=1)
        sig_wrap.pack(fill="x", padx=16, pady=(0,12))

        sig_sb = ttk.Scrollbar(sig_wrap, orient="vertical")
        sig_sb.pack(side="right", fill="y")

        self.sig_text = tk.Text(sig_wrap, height=4,
                                font=("Consolas", 8),
                                bg=C["surface2"], fg=C["pqc"],
                                insertbackground=C["pqc"],
                                selectbackground=C["pqc2"],
                                selectforeground=C["text"],
                                relief="flat", bd=8, wrap="word",
                                highlightthickness=0,
                                yscrollcommand=sig_sb.set)
        sig_sb.config(command=self.sig_text.yview)
        self.sig_text.pack(fill="x")

        # ───────────────────────────────────────────────────────────────────
        # SECCIÓN 5: Barra de acciones
        # ───────────────────────────────────────────────────────────────────
        self.action_bar = tk.Frame(body, bg=C["bg"])
        self.action_bar.pack(fill="x", pady=(0, 10))

        # Botones clásicos/KEM
        self.btn_encrypt = self._action_btn(self.action_bar, "  🔒  Cifrar  ",
                                            self._encrypt, C["accent"], C["accent2"],
                                            font_size=10, bold=True)
        self.btn_encrypt.pack(side="left", padx=(0,8), ipady=8, ipadx=6)

        self.btn_decrypt = self._action_btn(self.action_bar, "  🔓  Descifrar  ",
                                            self._decrypt, C["surface2"], C["surface3"],
                                            fg=C["text"], font_size=10, bold=True)
        self.btn_decrypt.pack(side="left", ipady=8, ipadx=6)

        # Botones DSA (ocultos por defecto)
        self.btn_sign   = self._action_btn(self.action_bar, "  ✍  Firmar  ",
                                           self._dsa_sign, C["pqc2"], C["pqc_dim"],
                                           font_size=10, bold=True)
        self.btn_verify = self._action_btn(self.action_bar, "  ✔  Verificar  ",
                                           self._dsa_verify, C["surface2"], C["surface3"],
                                           fg=C["pqc"], font_size=10, bold=True)

        # Limpiar todo (derecha)
        self._text_btn(self.action_bar, "✕ Limpiar todo", self._clear_all,
                       C["text_muted"]).pack(side="right")

        # ───────────────────────────────────────────────────────────────────
        # SECCIÓN 6: Resultado
        # ───────────────────────────────────────────────────────────────────
        result_card = self._card(body)
        result_card.pack(fill="both", expand=True, pady=(0,0))

        out_hdr = tk.Frame(result_card, bg=C["surface"])
        out_hdr.pack(fill="x", padx=16, pady=(12,6))
        self.result_label_var = tk.StringVar(value="RESULTADO")
        tk.Label(out_hdr, textvariable=self.result_label_var,
                 font=("Segoe UI", 7, "bold"),
                 bg=C["surface"], fg=C["text_muted"]).pack(side="left")
        self._text_btn(out_hdr, "⎘ Copiar", self._copy_output,
                       C["accent"]).pack(side="right")

        out_wrap = tk.Frame(result_card, bg=C["surface"],
                            highlightbackground=C["border"], highlightthickness=1)
        out_wrap.pack(fill="both", expand=True, padx=16, pady=(0,12))

        out_sb = ttk.Scrollbar(out_wrap, orient="vertical")
        out_sb.pack(side="right", fill="y")

        self.output_text = tk.Text(out_wrap, height=6,
                                   font=("Consolas", 10),
                                   bg=C["surface"], fg=C["success"],
                                   insertbackground=C["success"],
                                   selectbackground=C["accent2"],
                                   selectforeground=C["text"],
                                   relief="flat", bd=10, wrap="word",
                                   state="disabled",
                                   highlightthickness=0,
                                   yscrollcommand=out_sb.set)
        out_sb.config(command=self.output_text.yview)
        self.output_text.pack(fill="both", expand=True)

        # ───────────────────────────────────────────────────────────────────
        # BARRA DE ESTADO
        # ───────────────────────────────────────────────────────────────────
        status_frame = tk.Frame(self, bg=C["surface"], height=28)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)

        tk.Frame(status_frame, bg=C["border"], width=1).pack(side="left", fill="y")
        self.status_icon_var = tk.StringVar(value="●")
        self.status_icon = tk.Label(status_frame, textvariable=self.status_icon_var,
                                    bg=C["surface"], fg=C["text_muted"],
                                    font=("Segoe UI", 9), padx=12)
        self.status_icon.pack(side="left")

        self.status_var = tk.StringVar(value="Listo — ninguna operación realizada")
        tk.Label(status_frame, textvariable=self.status_var,
                 bg=C["surface"], fg=C["text_dim"],
                 font=("Segoe UI", 8), anchor="w").pack(side="left", fill="x", expand=True)

        # Contador de chars del campo de entrada
        self.char_count_var = tk.StringVar(value="0 chars")
        tk.Label(status_frame, textvariable=self.char_count_var,
                 bg=C["surface"], fg=C["text_muted"],
                 font=("Segoe UI", 7), padx=16).pack(side="right")
        self.input_text.bind("<KeyRelease>", self._update_char_count)
        self.input_text.bind("<<Paste>>",    self._update_char_count)

    # ── Constructores de widgets ──────────────────────────────────────────────
    def _card(self, parent) -> tk.Frame:
        """Contenedor tipo card con fondo surface y borde sutil."""
        f = tk.Frame(parent, bg=C["surface"],
                     highlightbackground=C["border"],
                     highlightthickness=1)
        return f

    def _icon_btn(self, parent, text, cmd, bg,
                  fg=None, font_size=11) -> tk.Button:
        if fg is None:
            fg = C["text_dim"]
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg,
                         activebackground=bg,
                         activeforeground=C["text"],
                         relief="flat", bd=0,
                         font=("Segoe UI", font_size),
                         cursor="hand2", padx=6)

    def _text_btn(self, parent, text, cmd, fg) -> tk.Button:
        return tk.Button(parent, text=text, command=cmd,
                         bg=C["bg"], fg=fg,
                         activebackground=C["bg"],
                         activeforeground=C["text"],
                         relief="flat", bd=0,
                         font=("Segoe UI", 8),
                         cursor="hand2", padx=4)

    def _action_btn(self, parent, text, cmd, bg, active_bg,
                    fg=None, font_size=9, bold=False) -> tk.Button:
        if fg is None:
            fg = C["text"]
        weight = "bold" if bold else "normal"
        return tk.Button(parent, text=text, command=cmd,
                         bg=bg, fg=fg,
                         activebackground=active_bg,
                         activeforeground=fg,
                         relief="flat", bd=0,
                         font=("Segoe UI", font_size, weight),
                         cursor="hand2")

    def _badge(self, text, fg, bg, parent) -> tk.Label:
        return tk.Label(parent, text=text,
                        bg=bg, fg=fg,
                        font=("Segoe UI", 8))

    # ── Detección de modo y adaptación de UI ─────────────────────────────────
    def _on_algo_change(self):
        algo    = self.algo_var.get()
        is_kem  = _is_kem(algo)
        is_dsa  = _is_dsa(algo)
        is_cls  = not is_kem and not is_dsa

        # Chip de tipo
        if is_cls:
            chip_txt = "Clásico"
            chip_bg  = C["accent"]
        elif is_kem:
            chip_txt = "KEM Híbrido"
            chip_bg  = C["pqc2"]
        else:
            chip_txt = "Firma PQC"
            chip_bg  = C["pqc"]
        self.algo_chip_var.set(f" {chip_txt} ")
        self.algo_chip.config(bg=chip_bg)

        # Info lateral del algoritmo
        self.algo_info_var.set(self._algo_info(algo))

        # Show/hide credential panels (Password vs PQC Keys)
        if is_cls:
            self.pqc_panel.pack_forget()
            self.pw_panel.pack(fill="x", padx=0, pady=0)
            self.pw_entry.config(state="normal",
                                 bg=C["surface2"], fg=C["text"])
        else:  # KEM or DSA — both use asymmetric keys
            self.pw_panel.pack_forget()
            self.pqc_panel.pack(fill="x")
            if is_kem:
                self.pqc_mode_label.config(text="⚛ CLAVES KEM (Pública / Privada)")
            else:
                self.pqc_mode_label.config(text="⚛ CLAVES DE FIRMA DIGITAL")

        # Campo de firma (solo DSA)
        if is_dsa:
            self.sig_card.pack(fill="x", pady=(0, 10),
                               before=self.action_bar)
        else:
            self.sig_card.pack_forget()

        # Etiquetas de contexto
        if is_dsa:
            self.input_label_var.set("Paso 1: DOCUMENTO ORIGINAL (Texto sin cifrar)")
            self.result_label_var.set("RESULTADO DE VERIFICACIÓN DSA")
        elif is_kem:
            self.input_label_var.set("TEXTO DE ENTRADA  ·  texto a cifrar o token a descifrar")
            self.result_label_var.set("RESULTADO  ·  token cifrado o texto descifrado")
        else:
            self.input_label_var.set("TEXTO DE ENTRADA")
            self.result_label_var.set("RESULTADO")

        # Botones de acción
        if is_dsa:
            self.btn_encrypt.pack_forget()
            self.btn_decrypt.pack_forget()
            self.btn_sign.pack(side="left", padx=(0,8), ipady=8, ipadx=6)
            self.btn_verify.pack(side="left", ipady=8, ipadx=6)
        else:
            self.btn_sign.pack_forget()
            self.btn_verify.pack_forget()
            self.btn_encrypt.pack(side="left", padx=(0,8), ipady=8, ipadx=6)
            self.btn_decrypt.pack(side="left", ipady=8, ipadx=6)

    def _algo_info(self, algo: str) -> str:
        info_map = {
            "AES-256-GCM":   "Cifrado autenticado · Scrypt KDF\nNivel: Clásico 256-bit",
            "Fernet":        "AES-128 + HMAC-SHA256 · PBKDF2\nNivel: Clásico 128-bit",
        }
        base = _base(algo)
        if base == "ML-KEM-768":
            return "NIST FIPS 203 · Kyber nivel 3\nSeguridad: ~AES-192 post-cuántico"
        if base == "HQC-KEM":
            return "Basado en códigos lineales\nSeguridad: ~AES-128 post-cuántico"
        if base == "ML-DSA":
            return "NIST FIPS 204 · Dilithium-65\nNivel 3 · balance rendimiento/seg."
        if base == "SLH-DSA":
            return "NIST FIPS 205 · SPHINCS+-SHA2\nMáxima seguridad conservadora"
        return info_map.get(algo, "")

    # ── Helpers de contraseña ────────────────────────────────────────────────
    def _generate_password(self):
        import string
        import secrets
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pw = "".join(secrets.choice(chars) for _ in range(24))
        self.pw_var.set(pw)
        self.pw_entry.config(show="") # Show password when generated
        self._set_status("✓ Contraseña de 24 chars generada (cópiala!)", C["success"])

    def _paste_pw(self):
        try:
            self.pw_var.set(self.clipboard_get().strip())
        except tk.TclError:
            pass

    def _toggle_pw(self):
        self.pw_entry.config(
            show="" if self.pw_entry.cget("show") == "•" else "•"
        )

    def _update_pw_strength(self, *_):
        pw = self.pw_var.get()
        if not pw:
            self.pw_strength_var.set("")
            return
        score = sum([
            len(pw) >= 12,
            any(c.isupper() for c in pw),
            any(c.islower() for c in pw),
            any(c.isdigit() for c in pw),
            any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pw),
        ])
        labels = {0:"● Muy débil",1:"● Débil",2:"●● Aceptable",
                  3:"●●● Buena",4:"●●●● Fuerte",5:"●●●●● Muy fuerte"}
        colors = {0:C["danger"],1:C["danger"],2:C["warning"],
                  3:C["warning"],4:C["success"],5:C["success"]}
        self.pw_strength_var.set(f"Fuerza: {labels[score]}")

    # ── Clipboard helpers ────────────────────────────────────────────────────
    def _paste_input(self):
        try:
            text = self.clipboard_get()
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", text)
            self._update_char_count()
        except tk.TclError:
            pass

    def _paste_pub_key(self):
        try:
            self.pub_key_var.set(self.clipboard_get().strip())
        except tk.TclError:
            pass

    def _paste_priv_key(self):
        try:
            self.priv_key_var.set(self.clipboard_get().strip())
        except tk.TclError:
            pass

    def _paste_signature(self):
        """Pega contenido del portapapeles en el campo de firma."""
        try:
            sig = self.clipboard_get().strip()
            self.sig_text.config(state="normal")
            self.sig_text.delete("1.0", "end")
            self.sig_text.insert("1.0", sig)
        except tk.TclError:
            pass

    def _copy_pub_key(self):
        val = self.pub_key_var.get().strip()
        if val:
            self.clipboard_clear(); self.clipboard_append(val)
            self._set_status("✓ Clave pública copiada", C["success"])

    def _copy_output(self):
        content = self.output_text.get("1.0", "end").strip()
        if content:
            self.clipboard_clear(); self.clipboard_append(content)
            self._set_status("✓ Resultado copiado al portapapeles", C["success"])

    def _copy_signature(self):
        sig = self.sig_text.get("1.0", "end").strip()
        if sig:
            self.clipboard_clear(); self.clipboard_append(sig)
            self._set_status("✓ Firma copiada al portapapeles", C["pqc"])

    def _update_char_count(self, *_):
        text = self.input_text.get("1.0", "end").strip()
        self.char_count_var.set(f"{len(text)} chars")

    # ── Salida ────────────────────────────────────────────────────────────────
    def _set_output(self, text: str, color: str = None):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        if color:
            self.output_text.config(fg=color)
        self.output_text.config(state="disabled")

    def _set_status(self, msg: str, color: str = None):
        self.status_var.set(msg)
        icon_color = color if color else C["text_dim"]
        self.status_icon.config(fg=icon_color)

    # ── Limpieza ──────────────────────────────────────────────────────────────
    def _clear_all(self):
        self.input_text.delete("1.0", "end")
        self.sig_text.config(state="normal")
        self.sig_text.delete("1.0", "end")
        self._set_output("")
        self.pw_var.set("")
        self.pub_key_var.set("")
        self.priv_key_var.set("")
        self.char_count_var.set("0 chars")
        self._set_status("Campos limpiados")

    # ── Validaciones de entrada ───────────────────────────────────────────────
    def _get_text(self) -> str | None:
        text = self.input_text.get("1.0", "end").strip()
        print(f"[DEBUG UI] get_text: {len(text)} chars recogidos")
        if not text:
            messagebox.showwarning("Campo vacío",
                                   "Escribe o pega el texto de entrada.")
            return None
        return text

    def _get_password(self) -> str | None:
        pw = self.pw_var.get().strip()
        if not pw:
            messagebox.showwarning("Contraseña vacía",
                                   "Ingresa una contraseña.")
            return None
        return pw

    def _get_pub_key(self) -> str | None:
        k = self.pub_key_var.get().strip()
        print(f"[DEBUG UI] get_pub_key: {len(k)} chars recogidos")
        if not k:
            messagebox.showwarning(
                "Clave pública requerida",
                "Ingresa la clave pública o genera un par nuevo\n"
                "con el botón '⚙ Generar Par de Claves'."
            )
            return None
        return k

    def _get_priv_key(self) -> str | None:
        k = self.priv_key_var.get().strip()
        print(f"[DEBUG UI] get_priv_key: {len(k)} chars recogidos")
        if not k:
            messagebox.showwarning(
                "Clave privada requerida",
                "Ingresa la clave privada.\n"
                "Si no la tienes, genera un nuevo par de claves."
            )
            return None
        return k

    def _check_pqc(self) -> bool:
        if not _PQC_LOAD_OK:
            messagebox.showerror(
                "PQC no disponible",
                f"Las funciones post-cuánticas no están disponibles:\n\n{_PQC_ERROR}\n\n"
                "Asegúrate de ejecutar desde el entorno virtual pqc_env."
            )
            return False
        return True

    # ── Operaciones de cifrado / descifrado ───────────────────────────────────
    def _encrypt(self):
        algo = self.algo_var.get()
        print(f"[DEBUG Acción] _encrypt con algoritmo: {algo}")

        if algo == "AES-256-GCM":
            text = self._get_text()
            if not text: return
            pw = self._get_password()
            if not pw: return
            try:
                result = aes_gcm_encrypt(text, pw)
                self._set_output(result, C["success"])
                self._set_status("✓ Texto cifrado con AES-256-GCM", C["success"])
            except Exception as e:
                messagebox.showerror("Error al cifrar", str(e))
                self._set_status("✗ Error durante el cifrado", C["danger"])

        elif algo == "Fernet":
            text = self._get_text()
            if not text: return
            pw = self._get_password()
            if not pw: return
            try:
                result = fernet_encrypt(text, pw)
                self._set_output(result, C["success"])
                self._set_status("✓ Texto cifrado con Fernet", C["success"])
            except Exception as e:
                messagebox.showerror("Error al cifrar", str(e))
                self._set_status("✗ Error durante el cifrado", C["danger"])

        elif _is_kem(algo):
            if not self._check_pqc(): return
            text    = self._get_text()
            if not text: return
            pub_key = self._get_pub_key()
            if not pub_key: return
            base    = _base(algo)
            try:
                result = kem_encrypt(text, pub_key, base)
                self._set_output(result, C["success"])
                self._set_status(
                    f"✓ Cifrado con {base} (KEM + HKDF-SHA256 + AES-256-GCM)",
                    C["success"])
            except Exception as e:
                messagebox.showerror("Error al cifrar (PQC)", str(e))
                self._set_status("✗ Error en cifrado post-cuántico", C["danger"])

    def _decrypt(self):
        algo = self.algo_var.get()
        logger.info("_decrypt: algo=%s", algo)

        if algo == "AES-256-GCM":
            text = self._get_text()
            if not text: return
            pw = self._get_password()
            if not pw: return
            try:
                result = aes_gcm_decrypt(text, pw)
                self._set_output(result, C["text"])
                self._set_status("✓ Texto descifrado con AES-256-GCM", C["success"])
            except ValueError as e:
                messagebox.showerror("Error al descifrar", str(e))
                self._set_output("", C["danger"])
                self._set_status("✗ Descifrado fallido — verifica contraseña", C["danger"])
            except Exception as e:
                messagebox.showerror("Error inesperado", str(e))
                self._set_status("✗ Error inesperado", C["danger"])

        elif algo == "Fernet":
            text = self._get_text()
            if not text: return
            pw = self._get_password()
            if not pw: return
            try:
                result = fernet_decrypt(text, pw)
                self._set_output(result, C["text"])
                self._set_status("✓ Texto descifrado con Fernet", C["success"])
            except ValueError as e:
                messagebox.showerror("Error al descifrar", str(e))
                self._set_output("", C["danger"])
                self._set_status("✗ Descifrado fallido — verifica contraseña", C["danger"])
            except Exception as e:
                messagebox.showerror("Error inesperado", str(e))
                self._set_status("✗ Error inesperado", C["danger"])

        elif _is_kem(algo):
            if not self._check_pqc(): return
            text     = self._get_text()
            if not text: return
            priv_key = self._get_priv_key()
            if not priv_key: return
            base     = _base(algo)
            try:
                result = kem_decrypt(text, priv_key, base)
                self._set_output(result, C["text"])
                self._set_status(f"✓ Descifrado con {base}", C["success"])
            except ValueError as e:
                messagebox.showerror("Error al descifrar (PQC)", str(e))
                self._set_output("", C["danger"])
                self._set_status("✗ Descifrado PQC fallido — verifica clave privada",
                                  C["danger"])
            except Exception as e:
                messagebox.showerror("Error inesperado", str(e))
                self._set_status("✗ Error inesperado", C["danger"])

    # ── Operaciones de firma DSA ───────────────────────────────────────────────
    def _dsa_sign(self):
        if not self._check_pqc(): return
        logger.info("_dsa_sign: starting")
        text = self._get_text()
        if not text: return
        priv_key = self._get_priv_key()
        if not priv_key: return

        base = _base(self.algo_var.get())
        try:
            if base == "SLH-DSA":
                self._set_status("⏳ Firmando con SLH-DSA (puede tardar ~2s)…",
                                  C["warning"])
                self.update()

            data_bytes = text.encode("utf-8")
            signature  = dsa_sign(data_bytes, priv_key, base)

            # Mostrar firma en el campo dedicado de firma
            self.sig_text.config(state="normal")
            self.sig_text.delete("1.0", "end")
            self.sig_text.insert("1.0", signature)

            # También en resultado para facilitar copia
            self._set_output(
                f"✓ Firma {base} generada exitosamente.\n\n"
                f"La firma se ha rellenado automáticamente arriba en el recuadro 'Paso 2: FIRMA DIGITAL'.\n"
                f"Para que otra persona pueda verificar que tú escribiste esto:\n"
                f"  1. Dale el Documento Original (Paso 1).\n"
                f"  2. Dale esta Firma (Paso 2).\n"
                f"  3. Dale tu Clave Pública.",
                C["pqc"]
            )
            self._set_status(
                f"✓ Firma {base} generada — {len(signature)} chars", C["pqc"])

        except Exception as e:
            messagebox.showerror("Error al firmar (PQC)", str(e))
            self._set_status("✗ Error en firma post-cuántica", C["danger"])

    def _dsa_verify(self):
        if not self._check_pqc(): return
        logger.info("_dsa_verify: starting")
        text = self._get_text()
        if not text: return
        pub_key = self._get_pub_key()
        if not pub_key: return

        # Read signature from dedicated field
        signature = self.sig_text.get("1.0", "end").strip()
        logger.info("_dsa_verify: sig_len=%d", len(signature))
        if not signature:
            messagebox.showwarning(
                "Falta el sello/firma a verificar",
                "Para verificar, necesitas dos cosas:\n\n"
                "1. Introduce el DOCUMENTO ORIGINAL arriba.\n"
                "2. Pega la FIRMA DIGITAL en el campo de texto de en medio.\n\n"
                "Ambos deben corresponder exactamente."
            )
            return

        base = _base(self.algo_var.get())
        try:
            data_bytes = text.encode("utf-8")
            if base == "SLH-DSA":
                self._set_status("⏳ Verificando firma SLH-DSA…", C["warning"])
                self.update()
            valid = dsa_verify(data_bytes, signature, pub_key, base)

            if valid:
                self._set_output(
                    "✔  FIRMA VÁLIDA\n\n"
                    "Los datos son auténticos e íntegros.\n"
                    "La firma corresponde con la clave pública proporcionada.",
                    C["success"]
                )
                self._set_status(f"✓ Firma {base} VÁLIDA — datos auténticos", C["success"])
            else:
                self._set_output(
                    "✗  FIRMA INVÁLIDA\n\n"
                    "La firma NO corresponde con los datos o la clave pública.\n"
                    "Posibles causas:\n"
                    "  · Los datos fueron modificados\n"
                    "  · La firma está corrupta o incompleta\n"
                    "  · La clave pública es incorrecta",
                    C["danger"]
                )
                self._set_status(f"✗ Firma {base} INVÁLIDA", C["danger"])

        except Exception as e:
            messagebox.showerror("Error al verificar firma", str(e))
            self._set_status("✗ Error en verificación de firma", C["danger"])

    # ── Generación y diálogo de claves PQC ────────────────────────────────────
    def _generate_pqc_keypair(self):
        if not self._check_pqc(): return
        algo    = self.algo_var.get()
        base    = _base(algo)
        is_kem  = _is_kem(algo)
        is_dsa  = _is_dsa(algo)

        if not (is_kem or is_dsa):
            messagebox.showinfo("Info",
                "Selecciona un algoritmo PQC para generar claves.")
            return

        self._set_status("⏳ Generando par de claves…", C["warning"])
        self.update()

        try:
            if is_kem:
                pub, priv = generate_kem_keypair(base)
                tipo = "KEM"
            else:
                pub, priv = generate_sig_keypair(base)
                tipo = "DSA"

            self.pub_key_var.set(pub)
            self.priv_key_var.set(priv)
            self._pqc_pub_key  = pub
            self._pqc_priv_key = priv

            self._set_status(
                f"✓ Par de claves {base} ({tipo}) generado — "
                f"pub={len(pub)}c, priv={len(priv)}c  ·  ¡Guarda la clave privada!",
                C["pqc"]
            )
            self._show_keypair_dialog(base, pub, priv, tipo)

        except Exception as e:
            messagebox.showerror("Error al generar claves PQC", str(e))
            self._set_status("✗ Error al generar claves PQC", C["danger"])

    def _show_keypair_dialog(self, algo: str, pub: str, priv: str, tipo: str):
        dlg = tk.Toplevel(self)
        dlg.title(f"Par de Claves — {algo} ({tipo})")
        dlg.configure(bg=C["bg"])
        dlg.geometry("700x560")
        dlg.resizable(True, True)
        dlg.transient(self)
        dlg.grab_set()

        # Header del diálogo
        hdr = tk.Frame(dlg, bg=C["surface"], height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Frame(dlg, bg=C["pqc"], height=2).pack(fill="x")

        tk.Label(hdr, text="⚛", font=("Segoe UI", 18),
                 bg=C["surface"], fg=C["pqc"]).pack(side="left", padx=(16,8), pady=12)
        lbl_frm = tk.Frame(hdr, bg=C["surface"])
        lbl_frm.pack(side="left", pady=12)
        tk.Label(lbl_frm, text=f"Par de Claves {algo}",
                 font=("Segoe UI", 13, "bold"),
                 bg=C["surface"], fg=C["text"]).pack(anchor="w")
        tk.Label(lbl_frm, text=f"{tipo} · liboqs {_PQC_VERSION}",
                 font=("Segoe UI", 8),
                 bg=C["surface"], fg=C["pqc"]).pack(anchor="w")

        body = tk.Frame(dlg, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=20, pady=16)

        # Advertencia
        warn = tk.Frame(body, bg="#451a03",
                        highlightbackground=C["warning"],
                        highlightthickness=1)
        warn.pack(fill="x", pady=(0,16))
        tk.Label(warn,
                 text="⚠  Guarda la clave privada de forma segura.\n"
                      "    Si la pierdes, no podrás descifrar ni firmar.\n"
                      "    Nunca la compartas ni la almacenes en texto plano.",
                 font=("Segoe UI", 9),
                 bg="#451a03", fg=C["warning"],
                 justify="left").pack(padx=12, pady=10)

        def _key_block(parent, label, hint, value, fg, copy_label):
            frm = self._card(parent)
            frm.pack(fill="x", pady=(0,12))

            hrow = tk.Frame(frm, bg=C["surface"])
            hrow.pack(fill="x", padx=12, pady=(10,4))
            tk.Label(hrow, text=label,
                     font=("Segoe UI", 9, "bold"),
                     bg=C["surface"], fg=fg).pack(side="left")
            tk.Label(hrow, text=f"  {hint}",
                     font=("Segoe UI", 8),
                     bg=C["surface"], fg=C["text_muted"]).pack(side="left")
            tk.Label(hrow, text=f"{len(value)} chars",
                     font=("Segoe UI", 7),
                     bg=C["surface"], fg=C["text_muted"]).pack(side="right")

            txt_wrap = tk.Frame(frm, bg=C["surface2"],
                                highlightbackground=C["border"], highlightthickness=1)
            txt_wrap.pack(fill="x", padx=12, pady=(0,6))
            txt = tk.Text(txt_wrap, height=3,
                          font=("Consolas", 8),
                          bg=C["surface2"], fg=fg,
                          relief="flat", bd=6, wrap="word",
                          highlightthickness=0)
            txt.insert("1.0", value)
            txt.config(state="disabled")
            txt.pack(fill="x")

            btn_row = tk.Frame(frm, bg=C["surface"])
            btn_row.pack(fill="x", padx=12, pady=(0,10))
            tk.Button(btn_row, text=f"⎘ Copiar {copy_label}",
                      command=lambda v=value: (
                          dlg.clipboard_clear(), dlg.clipboard_append(v)),
                      bg=C["surface3"], fg=fg,
                      activebackground=C["border"],
                      activeforeground=fg,
                      relief="flat", bd=0,
                      font=("Segoe UI", 8, "bold"),
                      cursor="hand2",
                      padx=10, pady=4).pack(side="left")

        _key_block(body, "Clave Pública",  "Compartir con remitente / verificador",
                   pub,  C["success"], "clave pública")
        _key_block(body, "Clave Privada",  "SECRETO — jamás compartir",
                   priv, C["danger"],  "clave privada")

        tk.Button(dlg, text="  Entendido — cerrar  ",
                  command=dlg.destroy,
                  bg=C["accent"], fg=C["text"],
                  activebackground=C["accent2"],
                  relief="flat", bd=0,
                  font=("Segoe UI", 10, "bold"),
                  cursor="hand2",
                  padx=16, pady=8).pack(pady=(0,20))

    def _show_pqc_warning(self):
        messagebox.showwarning(
            "liboqs no disponible",
            f"Las funciones post-cuánticas (PQC) no están disponibles:\n\n"
            f"{_PQC_ERROR}\n\n"
            "Los algoritmos AES-256-GCM y Fernet siguen funcionando.\n\n"
            "Para habilitar PQC:\n"
            "  source pqc_env/bin/activate\n"
            "  python src/Encrypt.py"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Punto de entrada
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = CifradorApp()
    app.mainloop()
