from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import checks
import db


class LeakCheckParserTests(unittest.TestCase):
    def test_found(self) -> None:
        result = checks._parse_leakcheck(
            {
                "success": True,
                "found": 12,
                "fields": ["email", "password", "phone"],
                "sources": [{"name": "Example", "date": "2024-01"}, {"name": "", "date": ""}],
            }
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["found"], 12)
        self.assertEqual(result["fields"], ["email", "password", "phone"])
        self.assertEqual(result["sources"], [{"name": "Example", "date": "2024-01"}])
        self.assertEqual(result["source_count"], 1)

    def test_not_found(self) -> None:
        result = checks._parse_leakcheck({"success": False, "error": "Not found"})
        self.assertEqual(
            result, {"ok": True, "found": 0, "fields": [], "sources": [], "source_count": 0}
        )

    def test_api_error(self) -> None:
        result = checks._parse_leakcheck({"success": False, "error": "Something"})
        self.assertFalse(result["ok"])

    def test_garbage(self) -> None:
        self.assertFalse(checks._parse_leakcheck("nope")["ok"])


class XonParserTests(unittest.TestCase):
    def test_breach_summary(self) -> None:
        result = checks._parse_xon(
            {
                "BreachesSummary": {"site": "A; B ;"},
                "ExposedBreaches": {"breaches_details": [{"breach": "A"}]},
                "BreachMetrics": {
                    "xposed_data": [
                        {
                            "name": "data_Email addresses",
                            "children": [{"name": "data_Passwords", "value": 3}],
                        }
                    ],
                    "risk": [{"risk_label": "high", "risk_score": 80}],
                },
                "PastesSummary": {"cnt": 2},
            }
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["sites"], ["A", "B"])
        self.assertIn(("Пароли", 3), result["exposed"])
        self.assertEqual(result["risk"]["risk_label"], "high")
        self.assertEqual(result["pastes"], 2)

    def test_error_payload_is_empty(self) -> None:
        result = checks._parse_xon({"Error": "Not found"})
        self.assertFalse(result["found"])


class PrivacyTests(unittest.TestCase):
    def test_mask_email(self) -> None:
        self.assertEqual(checks.mask_email("john@example.com"), "jo***@example.com")
        self.assertEqual(checks.mask_email("a@example.com"), "a***@example.com")

    def test_email_is_not_stored_and_delete_works(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db.init(Path(tmp) / "bot.db")
            db.save_email_check(1, 3, "high", 7)
            row = db.get_user(1)
            self.assertIsNone(row["last_email"])
            self.assertEqual(row["last_breaches"], 3)
            self.assertEqual(row["last_sources"], 7)

            db.toggle_item(1, "passwords")
            self.assertEqual(db.done_items(1), {"passwords"})

            db.delete_user(1)
            self.assertIsNone(db.get_user(1))
            self.assertEqual(db.done_items(1), set())


if __name__ == "__main__":
    unittest.main()
