#!/usr/bin/env python3
"""
CONAN Framework - Eseguibile Windows
Doppio click per avviare senza terminale
"""

import sys
import os
from pathlib import Path

# Cambia directory al path del file
os.chdir(Path(__file__).parent)

# Aggiungi directory corrente al path
sys.path.insert(0, str(Path(__file__).parent))

# Avvia CONAN
if __name__ == "__main__":
    try:
        from conan_launcher import main
        main()
    except Exception as e:
        # In caso di errore, mostra messagebox
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("CONAN Error", f"Errore avvio CONAN:\n{str(e)}")
        except:
            print(f"Errore: {e}")