"""Security behavior at the upload and image HTTP boundaries."""

import importlib.util
import io
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

import flask

ROOT = Path(__file__).resolve().parents[1]
STUBBED = False


def load_route(name):
    """Load one route file without route/__init__.py, which installs
    requirements and can restart the process during import."""
    global STUBBED
    if "route" not in sys.modules:
        STUBBED = True
        package = types.ModuleType("route")
        package.__path__ = [str(ROOT / "route")]
        sys.modules["route"] = package
        tool = types.ModuleType("route.tool")
        tool.__path__ = [str(ROOT / "route" / "tool")]
        sys.modules["route.tool"] = tool
        func = types.ModuleType("route.tool.func")
        func.flask, func.os, func.re, func.html = flask, os, re, __import__("html")
        func.db_change = lambda query: query
        func.number_check = lambda data, f=0: str(data)
        sys.modules["route.tool.func"] = func

    spec = importlib.util.spec_from_file_location(f"route.{name}", ROOT / "route" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"route.{name}"] = module
    spec.loader.exec_module(module)
    return module


upload = load_route("edit_upload")
images = load_route("main_view_image")
if STUBBED:
    # Leave no stub behind for tests that import the real route package.
    for module_name in ("route.edit_upload", "route.main_view_image",
                        "route.tool.func", "route.tool", "route"):
        sys.modules.pop(module_name, None)


class UploadSecurityTest(unittest.TestCase):
    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.add_url_rule("/upload", view_func=upload.edit_upload, methods=["GET", "POST"])
        self.client = self.app.test_client()
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.execute("create table other (name text, data text)")
        self.conn.execute("create table html_filter (kind text, html text)")
        self.conn.execute("create table data (title text, data text)")
        self.conn.execute("insert into other values ('upload', '2')")
        self.conn.executemany(
            "insert into html_filter values ('extension', ?)",
            [("svg",), ("png",)],
        )
        self.image_dir = tempfile.TemporaryDirectory(dir=".")
        self.addCleanup(self.image_dir.cleanup)
        self.addCleanup(self.conn.close)
        self.mocks = {
            "get_db_connect": Mock(return_value=self.conn),
            "ip_check": Mock(return_value="127.0.0.1"),
            "ip_or_user": Mock(return_value=1),
            "acl_check": AsyncMock(return_value=0),
            "captcha_post": AsyncMock(return_value=0),
            "re_error": AsyncMock(side_effect=lambda conn, code: flask.Response(str(code), status=400)),
            "redirect": Mock(side_effect=lambda conn, path: flask.redirect(path)),
            "load_image_url": Mock(return_value=self.image_dir.name),
            "sha224_replace": Mock(return_value="stored-hash"),
            "render_set": Mock(),
            "history_plus": Mock(),
            "get_time": Mock(return_value="now"),
        }
        patcher = patch.multiple(upload, create = True, **self.mocks)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_anonymous_get_and_post_redirect_before_other_processing(self):
        for method in ("get", "post"):
            with self.subTest(method=method):
                response = getattr(self.client, method)("/upload")
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], "/login")
        self.mocks["acl_check"].assert_not_awaited()
        self.mocks["captcha_post"].assert_not_awaited()
        self.assertEqual(self.conn.execute("select count(*) from data").fetchone()[0], 0)

    def test_authenticated_svg_upload_is_stored(self):
        self.mocks["ip_check"].return_value = "tester"
        self.mocks["ip_or_user"].return_value = 0
        for filename, stored in (("vector.svg", "stored-hash.svg"),
                                 ("vector.SVG", "stored-hash.SVG")):
            with self.subTest(filename=filename):
                (Path(self.image_dir.name) / stored).unlink(missing_ok=True)
                self.conn.execute("delete from data")
                response = self.client.post(
                    "/upload", data={"f_data[]": (io.BytesIO(b"<svg/>"), filename)},
                    content_type="multipart/form-data",
                )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], "/w/file:" + filename)
                self.assertEqual((Path(self.image_dir.name) / stored).read_bytes(), b"<svg/>")
                self.assertEqual(
                    self.conn.execute("select title from data").fetchone()[0],
                    "file:" + filename,
                )

    def test_authenticated_raster_upload_still_works(self):
        self.mocks["ip_check"].return_value = "tester"
        self.mocks["ip_or_user"].return_value = 0
        response = self.client.post(
            "/upload", data={"f_data[]": (io.BytesIO(b"png bytes"), "photo.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/w/file:photo.png")
        self.assertEqual((Path(self.image_dir.name) / "stored-hash.png").read_bytes(), b"png bytes")
        self.assertEqual(self.conn.execute("select title from data").fetchone()[0], "file:photo.png")

    def test_authenticated_upload_still_enforces_configured_size(self):
        self.mocks["ip_check"].return_value = "tester"
        self.mocks["ip_or_user"].return_value = 0
        response = self.client.post(
            "/upload", data={"f_data[]": (io.BytesIO(b"x" * 2_000_001), "large.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_data(as_text=True), "17")
        self.assertEqual(list(Path(self.image_dir.name).iterdir()), [])


class ImageResponseSecurityTest(unittest.TestCase):
    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.add_url_rule("/image/<path:name>", view_func=images.main_view_image)
        self.client = self.app.test_client()
        self.image_dir = tempfile.TemporaryDirectory(dir=".")
        self.addCleanup(self.image_dir.cleanup)
        relative_image_dir = os.path.relpath(self.image_dir.name, self.app.root_path)
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.addCleanup(self.conn.close)
        patcher = patch.multiple(
            images,
            create = True,
            get_db_connect=Mock(return_value=self.conn),
            acl_check=AsyncMock(return_value=0),
            load_image_url=Mock(return_value=relative_image_dir),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_inline_images_keep_real_mime_types(self):
        for suffix, mime in (("png", "image/png"), ("jpg", "image/jpeg"),
                             ("jpeg", "image/jpeg"), ("gif", "image/gif"),
                             ("webp", "image/webp")):
            with self.subTest(suffix=suffix):
                (Path(self.image_dir.name) / ("sample." + suffix)).write_bytes(b"image bytes")
                with self.client.get("/image/sample." + suffix + ".cache_v12") as response:
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.mimetype, mime)
                    self.assertNotIn("attachment", response.headers.get("Content-Disposition", ""))
                    self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
                    self.assertIn("sandbox", response.headers.get("Content-Security-Policy", ""))

    def test_svg_keeps_its_type_but_never_renders_as_a_document(self):
        (Path(self.image_dir.name) / "sample.svg").write_bytes(b"<svg/>")
        with self.client.get("/image/sample.svg.cache_v12") as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, "image/svg+xml")
            self.assertIn("attachment", response.headers["Content-Disposition"])
            self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertIn("sandbox", response.headers.get("Content-Security-Policy", ""))

    def test_other_files_download_as_octet_stream(self):
        for suffix in ("html", "txt"):
            with self.subTest(suffix=suffix):
                (Path(self.image_dir.name) / ("sample." + suffix)).write_bytes(b"<script>alert(1)</script>")
                with self.client.get("/image/sample." + suffix) as response:
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.mimetype, "application/octet-stream")
                    self.assertIn("attachment", response.headers["Content-Disposition"])
                    self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
                    self.assertIn("sandbox", response.headers.get("Content-Security-Policy", ""))


if __name__ == "__main__":
    unittest.main()
