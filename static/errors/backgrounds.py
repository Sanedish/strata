"""Generates the background images of the error pages and writes them into 403.html, 404.html and 502.html.

    python static/errors/backgrounds.py

Each page gets 5 images of 40 x 24 pixels (WebP, a few hundred bytes each), inlined as data: URIs because the pages
are copied to a drive as single files. The page shows one at random, stretched and blurred by the browser.

An image is a few soft pools of colour from the page's palette, blended in OKLab (so mixes stay clean instead of
turning grey) and bent by a slow sine warp. Fixed seeds: running this again gives the same images.
"""
import base64
import io
import math
import os
import random
import re

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
W, H, COUNT = 40, 24, 5

# OKLCH (lightness, chroma, hue in degrees); the first colour is the base the pools sit on
PALETTES = {
    "404": [(0.22, 0.05, 255), (0.55, 0.11, 215), (0.82, 0.06, 210), (0.78, 0.12, 60), (0.45, 0.10, 280)],  # fjord dusk
    "403": [(0.22, 0.07, 18), (0.58, 0.17, 35), (0.78, 0.14, 70), (0.88, 0.05, 85), (0.42, 0.12, 5)],       # clay kiln
    "502": [(0.24, 0.03, 240), (0.60, 0.12, 145), (0.83, 0.13, 105), (0.68, 0.08, 215), (0.45, 0.06, 260)], # storm, lichen
}


def oklab_to_srgb(lab):
    """OKLab (..., 3) -> sRGB 0..255 (Björn Ottosson's matrices)."""
    l_, m_, s_ = np.moveaxis(lab @ np.array([[1, 1, 1], [0.3963377774, -0.1055613458, -0.0894841775],
                                             [0.2158037573, -0.0638541728, -1.2914855480]]), -1, 0)
    lms = np.stack([l_ ** 3, m_ ** 3, s_ ** 3], -1)
    rgb = lms @ np.array([[4.0767416621, -1.2684380046, -0.0041960863], [-3.3077115913, 2.6097574011, -0.7034186147],
                          [0.2309699292, -0.3413193965, 1.7076147010]])
    rgb = np.clip(rgb, 0, 1)
    rgb = np.where(rgb <= 0.0031308, 12.92 * rgb, 1.055 * rgb ** (1 / 2.4) - 0.055)
    return (rgb * 255 + 0.5).astype(np.uint8)


def lch(l, c, h, rnd):
    """A palette colour, nudged a little so no two images share exact tones."""
    l, c, h = l + rnd.uniform(-0.04, 0.04), c * rnd.uniform(0.8, 1.15), math.radians(h + rnd.uniform(-10, 10))
    return np.array([l, c * math.cos(h), c * math.sin(h)])


def image(palette, rnd):
    y, x = np.mgrid[0:H, 0:W].astype(float)
    x, y = x / (W - 1), y / (H - 1) * H / W  # square units, so pools stay round
    for _ in range(2):  # slow warp: bends the pools into drifts instead of circles
        f, a, p, q = rnd.uniform(2, 5), rnd.uniform(0.04, 0.1), rnd.uniform(0, 6.3), rnd.uniform(0, 6.3)
        x, y = x + a * np.sin(f * y + p), y + a * np.sin(f * x + q)
    base = lch(*palette[0], rnd)
    acc, wsum = base * 0.12, np.full((H, W), 0.12)
    acc = np.broadcast_to(acc, (H, W, 3)).copy()
    for col in rnd.sample(palette[1:], k=rnd.randint(3, 4)):
        cx, cy = rnd.uniform(-0.15, 1.15), rnd.uniform(-0.15, 0.75)  # some centres sit off the edge and bleed in
        r = rnd.uniform(0.12, 0.3)
        w = (np.exp(-((x - cx) ** 2 + (y - cy) ** 2) / (2 * r * r)) * rnd.uniform(0.7, 1.3)) ** 1.6  # ** keeps pools apart
        acc += w[..., None] * lch(*col, rnd)
        wsum += w
    lab = acc / wsum[..., None]
    lab[..., 0] -= 0.06 * ((x - 0.5) ** 2 + (y - 0.3) ** 2)  # a soft vignette
    buf = io.BytesIO()
    Image.fromarray(oklab_to_srgb(lab)).save(buf, "WEBP", quality=72, method=6)
    return "data:image/webp;base64," + base64.b64encode(buf.getvalue()).decode()


def main():
    for code, palette in PALETTES.items():
        rnd = random.Random("strata-error-" + code)
        uris = [image(palette, rnd) for _ in range(COUNT)]
        path = os.path.join(HERE, code + ".html")
        html = open(path, encoding="utf-8").read()
        # /*BG0*/: the image shown without scripts (the dashboard's Preview); /*BG*/: the list the script picks from
        html, a = re.subn(r"/\*BG0\*/.*?/\*BG0\*/", lambda _: '/*BG0*/url("%s")/*BG0*/' % uris[0], html, flags=re.S)
        html, b = re.subn(r"/\*BG\*/.*?/\*BG\*/", lambda _: "/*BG*/" + ",".join('"%s"' % u for u in uris) + "/*BG*/", html, flags=re.S)
        assert a == b == 1, path
        open(path, "w", encoding="utf-8", newline="\n").write(html)
        print(code, sum(len(u) for u in uris), "bytes inlined")


if __name__ == "__main__":
    main()
