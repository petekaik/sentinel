"""The app shell: the manifest and the icons, and the ONE caching exception.

WHY THIS FILE EXISTS SEPARATELY FROM web.py, AND WHY IT IS NOT A LOOPHOLE

`web.py`'s whole contract is that nothing in the response path is cacheable: a
cached 200 served while the collector is dead is a false GREEN, and that page is
the only dead-man switch there is. So the header is the mechanism.

That rule is about OBSERVATIONS. An icon is not an observation -- it is a
constant of the image, it says nothing about the fleet, and serving it from a
cache cannot make anyone believe something untrue. Keeping the exception in its
own module, with its own name, is what stops it from spreading: there is exactly
one place that may answer with a cache header, and this is it.

WHAT IS NOT HERE: A SERVICE WORKER. iOS installs to the home screen without one,
so a service worker would exist only to cache -- and the only thing worth
caching on this page is the thing that must never be cached.
"""

import json
import os

# A day. The icons change only when the image does, and a redeploy that renames
# them gets a new URL in the manifest rather than a stale body.
CACHE_CONTROL = "public, max-age=86400"

_HERE = os.path.dirname(os.path.abspath(__file__))

# url path -> (file beside this module, content type). Adding an entry here is
# adding a cacheable response, so it is deliberately one line per asset and
# deliberately a short list.
ASSETS = {
    "/manifest.webmanifest": (None, "application/manifest+json"),
    "/icons/icon-180.png": ("icons/icon-180.png", "image/png"),
    "/icons/icon-512.png": ("icons/icon-512.png", "image/png"),
}


def read(relpath):
    """The bytes of a shell asset. Raises OSError, which the caller renders."""
    with open(os.path.join(_HERE, relpath), "rb") as fh:
        return fh.read()


def manifest():
    """The web app manifest.

    The theme colour and the background match the page's own --bg. They are two
    literals in two files on purpose: this one is a constant of the image and
    the other is the stylesheet's own token, and a shared import between them
    would couple the shell to the renderer for one hex value.
    """
    return json.dumps({
        "name": "sentinel",
        "short_name": "sentinel",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "background_color": "#0e1216",
        "theme_color": "#0e1216",
        "icons": [
            {"src": "/icons/icon-180.png", "sizes": "180x180",
             "type": "image/png"},
            {"src": "/icons/icon-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "any maskable"},
        ],
    }, indent=1)


def asset(relpath):
    """The body and content type for one asset, manifest included.

    Returns (bytes, ctype). Raises OSError for a file the image does not carry,
    which must render as a 500 rather than as an empty 200.
    """
    rel, ctype = ASSETS[relpath]
    if rel is None:
        return manifest().encode("utf-8"), ctype
    return read(rel), ctype
