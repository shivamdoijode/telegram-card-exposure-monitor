"""Unit tests. Uses only public test card numbers (e.g. 4111111111111111), never real cards."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from card_parser import analyze, luhn_valid, mask_digits, matches_watchlist  # noqa: E402


class CardParserTests(unittest.TestCase):
    def test_valid_card_is_masked(self):
        findings, candidates = analyze("Card: 4111111111111111|12|2030|123\nBank: Issuer: Example Bank")
        self.assertEqual(candidates, 1)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f.bin6, f.last4, f.expiry), ("411111", "1111", "12/2030"))
        self.assertFalse(hasattr(f, "cvv"))
        self.assertNotIn("4111111111111111", repr(f))

    def test_luhn_failure_is_rejected(self):
        findings, candidates = analyze("Card: 4111111111111112|12|2030|123")
        self.assertEqual((len(findings), candidates), (0, 1))
        self.assertFalse(luhn_valid("4111111111111112"))

    def test_tolerates_separators_labels_and_spacing(self):
        for text in [
            "CC ∣ 4111111111111111 ∣ 12 ∣ 30 ∣ 123",
            "CC: 4111 1111 1111 1111 | 12/30 | 123",
            "CC: 4111111111111111 | EXP: 12/2030 | CVV: 123",
            "Card: 4111\u200b111111111111|12|2030|123",
        ]:
            self.assertEqual(len(analyze(text)[0]), 1, text)

    def test_invalid_month_rejected(self):
        self.assertEqual(len(analyze("Card: 4111111111111111|13|2030|123")[0]), 0)

    def test_watchlist_matching(self):
        f = analyze("Card: 4111111111111111|12|2030|123\nBank: Issuer: Example Bank Ltd.")[0][0]
        text = "Bank: Issuer: Example Bank Ltd."
        self.assertTrue(matches_watchlist(f, text, ["example bank ltd"]))   # case/punctuation ignored
        self.assertTrue(matches_watchlist(f, text, ["411111"]))             # BIN prefix
        self.assertIsNone(matches_watchlist(f, text, ["Other Bank", "999999"]))

    def test_mask_digits(self):
        masked = mask_digits("4111111111111111|12|2030|123")
        self.assertNotIn("4111111111111111", masked)
        self.assertTrue(masked.startswith("411111******1111"))


if __name__ == "__main__":
    unittest.main()
