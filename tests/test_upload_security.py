"""Security headers on uploaded files served from /image/."""

import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import flask

ROOT = Path(__file__).resolve().parents[1]


def load_main_view_image():
    """Load the route without route/__init__.py, which installs
    requirements and can restart the process during import."""
    saved = {k: sys.modules.get(k) for k in ("route", "route.tool", "route.tool.func")}
    package = types.ModuleType("route")
    package.__path__ = [str(ROOT / "route")]
    func = types.ModuleType("route.tool.func")
    func.flask, func.re = flask, re
    sys.modules.update({"route": package, "route.tool": types.ModuleType("route.tool"), "route.tool.func": func})
    try:
        spec = importlib.util.spec_from_file_location("route.main_view_image", ROOT / "route" / "main_view_image.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


images = load_main_view_image()


class ImageResponseSecurityTest(unittest.TestCase):
    def setUp(self):
        app = flask.Flask(__name__)
        app.add_url_rule("/image/<path:name>", view_func=images.main_view_image)
        self.client = app.test_client()
        image_dir = tempfile.TemporaryDirectory(dir=".")
        self.addCleanup(image_dir.cleanup)
        self.dir = Path(image_dir.name)
        patcher = patch.multiple(
            images, create = True,
            get_db_connect = MagicMock(),
            acl_check = AsyncMock(return_value = 0),
            load_image_url = Mock(return_value = os.path.relpath(self.dir, app.root_path)),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def get(self, filename, body = b"x"):
        (self.dir / filename).write_bytes(body)
        response = self.client.get("/image/" + filename + ".cache_v1")
        self.addCleanup(response.close)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("sandbox", response.headers["Content-Security-Policy"])
        return response

    def test_svg_keeps_its_type_but_downloads(self):
        for filename in ("a.svg", "b.SVG"):
            with self.subTest(filename = filename):
                response = self.get(filename, b"<svg/>")
                self.assertEqual(response.mimetype, "image/svg+xml")
                self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_raster_images_stay_inline(self):
        response = self.get("a.png")
        self.assertEqual(response.mimetype, "image/png")
        self.assertIn("inline", response.headers["Content-Disposition"])


if __name__ == "__main__":
    unittest.main()
