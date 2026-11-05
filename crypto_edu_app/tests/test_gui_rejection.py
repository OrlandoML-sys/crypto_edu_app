import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tkinter.messagebox as mb
mb.showinfo = lambda *a, **k: None
mb.showerror = lambda *a, **k: (_ for _ in ()).throw(RuntimeError(a[1] if len(a) > 1 else str(a)))
mb.showwarning = lambda *a, **k: None
mb.askyesno = lambda *a, **k: True

from gui.app import CryptoLabApp

app = CryptoLabApp()
app.update()

# Mecanismos donde flipear un byte del dato publico DEBE producir rechazo/discordancia
deben_rechazar = ["hash", "sponge", "aead", "mac_hmac", "mac_cmac", "sig", "pke"]
fallas = []
for mid in deben_rechazar:
    app.select_mechanism(mid)
    app.update()
    app.alice_run()
    app.update()
    app.eve_bitflip()
    app.update()
    app.bob_run()
    app.update()
    label = app.bob_result_label.cget("text")
    ok = "RECHAZADO" in label or "ERROR" in label
    print(f"{mid:12s} -> {label}  {'OK' if ok else 'FALLO: deberia haber sido rechazado'}")
    if not ok:
        fallas.append(mid)

app.destroy()
if fallas:
    print("FALLAS:", fallas)
    sys.exit(1)
print("Todas las verificaciones de rechazo pasaron correctamente.")
