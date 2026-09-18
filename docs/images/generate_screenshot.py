"""
Generates docs/images/live-alert-output.png from this project's own real
captured live-test output (see README's Live test results section) - not
fabricated data. Re-run after a new live test if you want to refresh it:

    python3 docs/images/generate_screenshot.py

Requires Pillow (pip install pillow) and DejaVu Sans Mono, which ships by
default on most Linux distros including Kali.
"""
import os

from PIL import Image, ImageDraw, ImageFont

W, H = 1160, 420
BG = (13, 15, 20)
TITLEBAR = (32, 34, 40)
FG = (223, 227, 232)
DIM = (120, 128, 138)
GREEN = (98, 209, 150)
YELLOW = (230, 195, 100)
RED = (235, 120, 120)
CYAN = (110, 190, 230)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

mono = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
mono_bold = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
font = ImageFont.truetype(mono, 15)
font_b = ImageFont.truetype(mono_bold, 15)

# Title bar
d.rectangle([0, 0, W, 34], fill=TITLEBAR)
for i, c in enumerate([RED, YELLOW, GREEN]):
    d.ellipse([16 + i * 22, 12, 26 + i * 22, 22], fill=c)
title = "er723@ER723-lab: ~/recon-detector"
tw = d.textlength(title, font=font)
d.text(((W - tw) / 2, 9), title, font=font, fill=DIM)

# Terminal content
x0, y = 20, 52
lh = 21

def line(text, color=FG, bold=False, indent=0):
    global y
    f = font_b if bold else font
    d.text((x0 + indent, y), text, font=f, fill=color)
    y += lh

def wrapped_json(text, color):
    """Wrap a long JSON alert line across the terminal width."""
    global y
    max_width = W - x0 * 2
    words = text
    cur = ""
    for ch in words:
        test = cur + ch
        if d.textlength(test, font=font) > max_width:
            d.text((x0, y), cur, font=font, fill=color)
            y += lh
            cur = ch
        else:
            cur = test
    if cur:
        d.text((x0, y), cur, font=font, fill=color)
        y += lh
    y += 4

line("$ sudo python3 recon_detector.py --iface eth0", color=CYAN, bold=True)
line("recon-detector starting on iface=eth0 (tcp_vertical>=15/10s or >=30/300s, ...)", color=DIM)
y += 6
line("[HEARTBEAT] recon-detector alive, tracking 41 active tracker entr(y/ies)", color=DIM)
y += 6

wrapped_json(
    '{"timestamp": "2026-09-12T13:53:46Z", "alert_type": "ARP_SCAN", "source_ip": '
    '"192.168.1.4", "severity": "low", "protocol": "ARP", "count": 10, '
    '"window_seconds": 10, "sample_hosts": ["192.168.1.11", "192.168.1.14", "..."]}',
    YELLOW,
)
wrapped_json(
    '{"timestamp": "2026-09-12T13:58:24Z", "alert_type": "TCP_VERTICAL_SCAN", '
    '"source_ip": "192.168.1.4", "severity": "high", "destination_ip": "192.168.1.27", '
    '"protocol": "TCP", "last_flags": "S", "count": 15, "window_seconds": 10, '
    '"sample": [19, 21, 22, 23, 24, 25, 31, 40, 53, "..."]}',
    RED,
)
wrapped_json(
    '{"timestamp": "2026-09-12T14:02:28Z", "alert_type": "SLOW_TCP_VERTICAL_SCAN", '
    '"source_ip": "192.168.1.4", "severity": "medium", "destination_ip": "192.168.1.27", '
    '"protocol": "TCP", "count": 72, "window_seconds": 300, "note": '
    '"stealthy/slow-timed scan pattern"}',
    YELLOW,
)

y += 4
line("[HEARTBEAT] recon-detector alive, tracking 42 active tracker entr(y/ies)", color=DIM)
line("[cleanup] pruned 1 idle tracker(s), 1 old cooldown entr(y/ies)", color=DIM)

footer = (
    "Real output, captured during live Nmap testing on a Kali VM "
    "\u2014 see README \u00a7 Live test results"
)
d.text((x0, H - 30), footer, font=font, fill=DIM)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live-alert-output.png")
img.save(out_path)
print(f"saved to {out_path}")
