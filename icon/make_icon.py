#!/usr/bin/env python3
# Erzeugt das App-Icon für harbour-sfmail.
#  * Hintergrund: "amerikanischer Briefkasten" — scharfe Ecken unten,
#    Halbkreis oben (Silhouette wie die original Mail-App), blau.
#  * Dahinter ein Briefumschlag als Strichzeichnung (etwas breiter als das
#    Schloss): Striche neon-blau auf dem Hintergrund, im Schloss-Bereich neon-rot.
#  * Davor ein gelbes Vorhängeschloss (etwas kleiner, damit der Umschlag breiter
#    wirkt).
# Gerendert bei 1024 px und auf die SFOS-Icon-Größen heruntergerechnet (LANCZOS
# → Kantenglättung).
import os
from PIL import Image, ImageDraw, ImageChops

S = 4                      # Supersampling (256-Koordinaten * 4 = 1024)
N = 256 * S
def s(v): return int(round(v * S))

# --- Farben ----------------------------------------------------------------
BG_TOP    = (28, 78, 134)      # blau, oben etwas heller
BG_BOTTOM = (15, 48, 94)       # blau, unten dunkler
NEON_BLUE = (0, 229, 255)
NEON_RED  = (255, 23, 68)
LOCK_TOP  = (255, 213, 79)     # gelb
LOCK_BOT  = (255, 179, 0)
SHACKLE   = (207, 216, 220)
KEYHOLE   = (90, 64, 0)

# --- Hintergrund-Silhouette (Arch / Briefkasten) ---------------------------
# Nutzt fast die volle Fläche (nur wenig Rand, damit nichts geclippt wird).
X0, X1 = 10, 246               # linke/rechte Kante
Y_S    = 126                   # Oberkante der geraden Seiten (Start Halbkreis)
Y_B    = 248                   # Unterkante (scharfe Ecken)
R      = (X1 - X0) // 2        # Halbkreis-Radius (= 118, Kuppel-Spitze bei y≈8)
CX     = (X0 + X1) // 2

def make_shape_mask():
    m = Image.new("L", (N, N), 0)
    d = ImageDraw.Draw(m)
    # gerader Korpus mit scharfen unteren Ecken
    d.rectangle([s(X0), s(Y_S), s(X1), s(Y_B)], fill=255)
    # Halbkreis oben (obere Hälfte der Ellipse)
    d.pieslice([s(X0), s(Y_S - R), s(X1), s(Y_S + R)], 180, 360, fill=255)
    return m

def make_background():
    grad = Image.new("RGB", (1, N))
    for y in range(N):
        t = y / (N - 1)
        grad.putpixel((0, y), tuple(int(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t) for i in range(3)))
    grad = grad.resize((N, N))
    out = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    out.paste(grad, (0, 0), make_shape_mask())
    return out

# --- Briefumschlag (Strichzeichnung), breiter als das Schloss --------------
# Bewusst höher angesetzt: die Unterkante (EY1) liegt klar ÜBER der Schloss-
# Unterkante, damit die roten Linien nicht an der unteren Schlosskante laufen.
EX0, EX1 = 44, 212             # Umschlagbreite (168) > Schloss (84)
EY0, EY1 = 118, 194
FLAP_Y   = EY0 + 48            # Spitze der Umschlagklappe
LW       = 6                   # Strichbreite (256-Raum)

def draw_envelope(color):
    layer = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    w = s(LW)
    def line(a, b):
        d.line([s(a[0]), s(a[1]), s(b[0]), s(b[1])], fill=color + (255,), width=w)
    # Rechteck
    line((EX0, EY0), (EX1, EY0)); line((EX1, EY0), (EX1, EY1))
    line((EX1, EY1), (EX0, EY1)); line((EX0, EY1), (EX0, EY0))
    # Klappe (V)
    line((EX0, EY0), (CX, FLAP_Y)); line((EX1, EY0), (CX, FLAP_Y))
    # runde Ecken/Enden kaschieren
    for p in [(EX0, EY0), (EX1, EY0), (EX1, EY1), (EX0, EY1), (CX, FLAP_Y)]:
        d.ellipse([s(p[0]) - w//2, s(p[1]) - w//2, s(p[0]) + w//2, s(p[1]) + w//2], fill=color + (255,))
    return layer

# --- Schloss (größer, nach oben länglicher) ---------------------------------
BX0, BX1 = 84, 172             # Schlosskörper (Breite 88, minimal breiter)
BY0, BY1 = 138, 226            # höher beginnend (länglicher), tiefer endend
BRAD     = 14
SH_CX, SH_TOP = CX, 84         # Bügel deutlich höher gezogen
SH_R     = 33                  # größerer Radius (kräftiger)
SH_W     = 15

def lock_body_mask():
    m = Image.new("L", (N, N), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([s(BX0), s(BY0), s(BX1), s(BY1)], radius=s(BRAD), fill=255)
    return m

def draw_lock(base):
    # Bügel (hinter dem Körper)
    d = ImageDraw.Draw(base)
    d.arc([s(SH_CX - SH_R), s(SH_TOP), s(SH_CX + SH_R), s(SH_TOP + 2 * SH_R)],
          180, 360, fill=SHACKLE + (255,), width=s(SH_W))
    # gerade Bügelenden bis in den Körper
    for x in (SH_CX - SH_R, SH_CX + SH_R):
        d.line([s(x), s(SH_TOP + SH_R), s(x), s(BY0 + 6)], fill=SHACKLE + (255,), width=s(SH_W))
    # Körper mit vertikalem Gelb-Verlauf
    body = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    grad = Image.new("RGB", (1, N))
    for y in range(N):
        t = y / (N - 1)
        grad.putpixel((0, y), tuple(int(LOCK_TOP[i] + (LOCK_BOT[i] - LOCK_TOP[i]) * t) for i in range(3)))
    grad = grad.resize((N, N))
    body.paste(grad, (0, 0), lock_body_mask())
    base.alpha_composite(body)
    # Schlüsselloch (an das größere Schloss angepasst)
    d = ImageDraw.Draw(base)
    kx, ky = CX, 188
    d.ellipse([s(kx - 8), s(ky - 8), s(kx + 8), s(ky + 8)], fill=KEYHOLE + (255,))
    d.polygon([s(kx - 4), s(ky), s(kx + 4), s(ky), s(kx + 7), s(212), s(kx - 7), s(212)],
              fill=KEYHOLE + (255,))

# --- Komposition ------------------------------------------------------------
def render():
    base = make_background()
    # Umschlag neon-blau hinter dem Schloss
    base.alpha_composite(draw_envelope(NEON_BLUE))
    # Schloss davor
    draw_lock(base)
    # Umschlag neon-rot, nur im Schloss-Bereich, über dem Schloss
    red = draw_envelope(NEON_RED)
    red_alpha = red.getchannel("A")
    clip = ImageChops.multiply(red_alpha, lock_body_mask())
    base.paste(red, (0, 0), clip)
    # auf Silhouette beschneiden (Striche/Bügel, die überstehen, wegschneiden)
    base.putalpha(ImageChops.multiply(base.getchannel("A"), make_shape_mask()))
    return base

def main():
    master = render()
    root = os.path.dirname(os.path.abspath(__file__))
    out_root = os.path.join(root, "..", "src", "icons")
    for size in (86, 108, 128, 172):
        img = master.resize((size, size), Image.LANCZOS)
        d = os.path.join(out_root, "%dx%d" % (size, size))
        os.makedirs(d, exist_ok=True)
        img.save(os.path.join(d, "harbour-sfmail.png"))
        print("wrote", os.path.join(d, "harbour-sfmail.png"))
    master.resize((256, 256), Image.LANCZOS).save(os.path.join(root, "preview-256.png"))
    print("wrote preview-256.png")

if __name__ == "__main__":
    main()
