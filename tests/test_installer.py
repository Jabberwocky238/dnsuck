"""Exercise release installation without network access or system-directory writes."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dnsuck-installer-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.prefix = self.path / "prefix"
        self.assets = self.path / "assets"
        self.assets.mkdir()
        self.mockbin = self.path / "mockbin"
        self.mockbin.mkdir()
        self.env = dict(os.environ, PATH=str(self.mockbin) + os.pathsep + os.environ["PATH"],
                        HOME=str(self.path / "home"), INSTALL_TEST_ASSETS=str(self.assets),
                        INSTALL_TEST_OS="Linux", INSTALL_TEST_ARCH="x86_64", INSTALL_TEST_UID="1000")
        self.mock("id", '#!/bin/sh\nprintf "%s\\n" "$INSTALL_TEST_UID"\n')
        self.mock("uname", '#!/bin/sh\ncase "$1" in -s) echo "$INSTALL_TEST_OS";; -m) echo "$INSTALL_TEST_ARCH";; esac\n')
        self.mock("curl", '''#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith('https://'))
shutil.copyfile(pathlib.Path(os.environ['INSTALL_TEST_ASSETS']) / url.rsplit('/', 1)[1], args[args.index('-o') + 1])
''')
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            self.archive(target)

    def mock(self, name, text):
        path = self.mockbin / name
        path.write_text(text)
        path.chmod(0o755)

    def archive(self, target, bad_path=False):
        path = self.assets / f"dnsuck-{target}.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, content in [("dnsuckd", b"#!/bin/sh\necho dnsuckd-test\n"),
                                  ("dnsuck", b"#!/bin/sh\necho dnsuck-test\n"), ("VERSION", b"v1.2.3\n")]:
                entry = tarfile.TarInfo("../escaped" if bad_path and name == "dnsuck" else name)
                entry.mode = 0o755
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        path.with_name(path.name + ".sha256").write_text(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n")

    def run_installer(self, *args, default_prefix=False):
        command = ["bash", str(ROOT / "install.sh"), "--repo", "example/dnsuck"]
        if not default_prefix:
            command += ["--prefix", str(self.prefix)]
        return subprocess.run([*command, *args], env=self.env, text=True, capture_output=True, timeout=15)

    def test_platform_selection_install_upgrade_uninstall(self):
        for system, arch in [("Linux", "x86_64"), ("Linux", "aarch64")]:
            with self.subTest(system=system, arch=arch):
                self.env.update(INSTALL_TEST_OS=system, INSTALL_TEST_ARCH=arch)
                for _ in range(2):
                    result = self.run_installer("--version", "v1.2.3")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    for binary in ("dnsuckd", "dnsuck"):
                        link = self.prefix / "bin" / binary
                        self.assertTrue(link.is_symlink())
                        self.assertEqual(subprocess.check_output([link], text=True).strip(), binary + "-test")
                data = self.prefix / "data/lmdb"
                data.mkdir(parents=True, exist_ok=True)
                (data / "keep").write_text("records")
                result = self.run_installer("--uninstall")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.prefix / "bin/dnsuck").is_symlink())
                self.assertFalse((self.prefix / "bin/dnsuckd").is_symlink())
                self.assertFalse((self.prefix / "lib/dnsuck").exists())
                self.assertTrue((data / "keep").exists())
                self.assertEqual(self.run_installer("--uninstall").returncode, 0)

    def test_legacy_cli_link_cleanup(self):
        for action in ((), ("--uninstall",)):
            self.assertEqual(self.run_installer().returncode, 0)
            legacy = self.prefix / "bin/cmd"
            legacy.symlink_to("../lib/dnsuck/old/cmd")
            self.assertEqual(self.run_installer(*action).returncode, 0)
            self.assertFalse(legacy.is_symlink())
        legacy.symlink_to("/unrelated/cmd")
        self.assertEqual(self.run_installer().returncode, 0)
        self.assertEqual(self.run_installer("--uninstall").returncode, 0)
        self.assertEqual(os.readlink(legacy), "/unrelated/cmd")

    def test_user_default_and_root_explicit_prefix(self):
        result = self.run_installer(default_prefix=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((Path(self.env["HOME"]) / ".local/bin/dnsuck").is_symlink())
        self.assertEqual(self.run_installer("--uninstall", default_prefix=True).returncode, 0)
        self.env["INSTALL_TEST_UID"] = "0"
        self.assertEqual(self.run_installer().returncode, 0)
        self.assertTrue((self.prefix / "bin/dnsuck").is_symlink())

    def test_checksum_and_archive_validation(self):
        checksum = self.assets / "dnsuck-x86_64-unknown-linux-gnu.tar.gz.sha256"
        checksum.write_text("0" * 64 + "  archive\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse(self.prefix.exists())
        self.archive("x86_64-unknown-linux-gnu", bad_path=True)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive contents", result.stderr)
        self.assertFalse(self.prefix.exists())

    def test_preserves_unrelated_files_and_links(self):
        (self.prefix / "bin").mkdir(parents=True)
        binary = self.prefix / "bin/dnsuck"
        binary.write_text("unrelated")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(binary.read_text(), "unrelated")
        binary.unlink()
        self.assertEqual(self.run_installer().returncode, 0)
        binary.unlink()
        binary.symlink_to("/unrelated/dnsuck")
        self.assertEqual(self.run_installer("--uninstall").returncode, 0)
        self.assertEqual(os.readlink(binary), "/unrelated/dnsuck")

    def test_release_packaging_matches_installer_contract(self):
        import shutil
        checkout = self.path / "checkout"
        (checkout / "scripts").mkdir(parents=True)
        (checkout / "target/release").mkdir(parents=True)
        script = checkout / "scripts/package-release.sh"
        shutil.copyfile(ROOT / "scripts/package-release.sh", script)
        for name in ("dnsuckd", "dnsuck"):
            (checkout / "target/release" / name).write_text("#!/bin/sh\necho packaged\n")
        result = subprocess.run(["bash", str(script), "v2.0.0", "x86_64-unknown-linux-gnu", str(self.assets)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_installer("--version", "v2.0.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(subprocess.check_output([self.prefix / "bin/dnsuck"], text=True).strip(), "packaged")

    def test_invalid_options_platform_and_version(self):
        for args in [("--version", "../bad"), ("--version", "v9"), ("--unknown",), ("--prefix", "/")]:
            self.assertNotEqual(self.run_installer(*args).returncode, 0)
        self.env["INSTALL_TEST_OS"] = "Darwin"
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.env["INSTALL_TEST_OS"] = "Linux"
        self.env["INSTALL_TEST_ARCH"] = "unsupported"
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertFalse(self.prefix.exists())
