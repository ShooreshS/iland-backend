import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("credential-inventory.py")
SPEC = importlib.util.spec_from_file_location("credential_inventory", SCRIPT)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class CredentialInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root), *args],
                              input=stdin, text=True, capture_output=True, check=False)

    def test_dotenv_values_and_commands_never_leave_file_or_execute(self):
        marker = self.root / "command-was-executed"
        secrets = ["sensitive-key-value-123", "other-secret-value-456"]
        self.write(".env", f'API_KEY={secrets[0]}\nexport TOKEN="{secrets[1]}"\nCOMMAND=$(touch "{marker}")\n')
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual({item["name"] for item in result["records"]}, {"API_KEY", "TOKEN", "COMMAND"})
        for secret in secrets:
            self.assertNotIn(secret, completed.stdout + completed.stderr)
        self.assertNotIn("touch", completed.stdout + completed.stderr)
        self.assertFalse(marker.exists())

    def test_multiline_dotenv_values_are_not_mistaken_for_names(self):
        self.write(".env", 'PRIVATE_KEY="first line\nSECRET_LOOKING_VALUE=inside\nlast line"\nAFTER=ok\n')
        records, _ = inventory.scan(self.root)
        self.assertEqual([(item["name"], item["line"]) for item in records], [("AFTER", 4), ("PRIVATE_KEY", 1)])

    def test_supported_references_and_precise_locations(self):
        self.write("app.ts", 'process.env.API_KEY; process.env["BRACKET_KEY"];\nBun.env.BUN_KEY; Deno.env.get("DENO_KEY");\n')
        self.write("app.py", 'os.environ["PYTHON_KEY"]\nos.environ.get("OPTIONAL_KEY", "fallback-secret")\nos.getenv("GETENV_KEY")\n')
        records, _ = inventory.scan(self.root)
        by_name = {item["name"]: item for item in records}
        self.assertEqual(set(by_name), {"API_KEY", "BRACKET_KEY", "BUN_KEY", "DENO_KEY", "PYTHON_KEY", "OPTIONAL_KEY", "GETENV_KEY"})
        self.assertEqual(by_name["DENO_KEY"], {"name": "DENO_KEY", "file": "app.ts", "line": 2, "source": "deno_env"})
        self.assertEqual(by_name["OPTIONAL_KEY"]["line"], 2)
        self.assertNotIn("fallback-secret", json.dumps(records))

    def test_symlinks_and_dependency_trees_are_skipped(self):
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other)
            (outside / ".env").write_text("EXTERNAL_SECRET=value")
            (self.root / ".env").symlink_to(outside / ".env")
            (self.root / "linked-directory").symlink_to(outside, target_is_directory=True)
            for directory in ("node_modules", ".git", "build", "dist", ".next", "vendor", ".gradle", "Pods", "tmp"):
                self.write(f"{directory}/.env", "IGNORED_SECRET=value")
            records, _ = inventory.scan(self.root)
            self.assertEqual(records, [])
            completed = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root / "linked-directory")],
                                       text=True, capture_output=True, check=False)
            self.assertNotEqual(completed.returncode, 0)

    def test_binary_oversized_and_irrelevant_files_are_not_scanned(self):
        (self.root / "binary.ts").write_bytes(b"process.env.BINARY_KEY\0")
        self.write("large.ts", "process.env.LARGE_KEY;" + " " * inventory.DEFAULT_MAX_FILE_BYTES)
        self.write("notes.txt", "process.env.IRRELEVANT_KEY")
        (self.root / "invalid.ts").write_bytes(b"process.env.INVALID_KEY\xff")
        records, skipped = inventory.scan(self.root)
        self.assertEqual(records, [])
        self.assertEqual({item["reason"] for item in skipped}, {"binary_file", "file_size_limit", "non_utf8_file"})

    def test_unknown_names_are_reported_without_exposure_claims(self):
        self.write("app.js", "process.env.EXISTING; process.env.LOCAL_ONLY;")
        completed = self.run_cli("--names-json", "-", stdin='["UNKNOWN_KEY", "EXISTING", "UNKNOWN_KEY"]')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "inventory_only")
        self.assertEqual(result["comparison"]["provided_names_without_local_reference"], ["UNKNOWN_KEY"])
        self.assertEqual(result["comparison"]["local_names_not_provided"], ["LOCAL_ONLY"])
        self.assertEqual(result["comparison"]["provided_names"], ["EXISTING", "UNKNOWN_KEY"])

    def test_name_file_is_accepted_and_value_maps_rejected_generically(self):
        names = self.write("names.json", '["VALID_NAME"]')
        accepted = self.run_cli("--names-json", str(names))
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        invalid_inputs = ['{"API_KEY":"NEVER_PRINT_SECRET"}', '["KEY=NEVER_PRINT_SECRET"]',
                          '["bad-name-NEVER_PRINT_SECRET"]', '[true]', '[12]', 'null',
                          '["1START"]', '["UNICODE_é"]', 'NEVER_PRINT_SECRET']
        for payload in invalid_inputs:
            with self.subTest(payload=payload):
                rejected = self.run_cli("--names-json", "-", stdin=payload)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, "")
                self.assertNotIn("NEVER_PRINT_SECRET", rejected.stderr)
                self.assertIn("names input must be a JSON array", rejected.stderr)

    def test_dotenv_values_are_not_scanned_as_code(self):
        self.write(".env", 'STRING="process.env.VALUE_THAT_IS_NOT_A_NAME"\n')
        records, _ = inventory.scan(self.root)
        self.assertEqual([record["name"] for record in records], ["STRING"])


if __name__ == "__main__":
    unittest.main()
