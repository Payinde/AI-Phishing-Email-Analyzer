import unittest

from ai_explainer import (
    ai_sentence_is_acceptable,
    build_default_risk_sentence,
    build_evidence_sentence,
    has_invalid_single_letter_word,
    has_repetitive_words,
)


class TestAIExplainerGuardrails(unittest.TestCase):

    def test_repetitive_words_are_detected(self):
        self.assertTrue(
            has_repetitive_words(
                "vulnerability vulnerabilities"
            )
        )

        self.assertTrue(
            has_repetitive_words(
                "pos posing a security risk"
            )
        )

    def test_normal_sentence_is_accepted(self):
        sentence = (
            "The indicators may represent credential theft "
            "or fraudulent activity."
        )

        self.assertFalse(
            has_repetitive_words(sentence)
        )

        self.assertTrue(
            ai_sentence_is_acceptable(sentence)
        )

    def test_unsupported_ai_claim_is_rejected(self):
        sentence = (
            "Multiple URLs confirm that this is definitely phishing."
        )

        self.assertFalse(
            ai_sentence_is_acceptable(sentence)
        )

    def test_invalid_single_letter_fragment_is_rejected(self):
        self.assertTrue(
            has_invalid_single_letter_word(
                "This creates a high security risk d due to fraud."
            )
        )

        self.assertFalse(
            has_invalid_single_letter_word(
                "This creates a high security risk."
            )
        )

    def test_verified_evidence_uses_exact_url_count(self):
        analysis = {
            "risk_level": "High",
            "score": 70,
            "urls": [
                "https://account-live.example.test/reactivate",
            ],
            "indicators": [
                {
                    "category": "Suspicious language",
                    "detail": "Test indicator",
                    "points": 15,
                },
                {
                    "category": "Brand impersonation",
                    "detail": "Test indicator",
                    "points": 25,
                },
            ],
        }

        evidence = build_evidence_sentence(
            analysis
        )

        self.assertIn(
            "Brand impersonation",
            evidence,
        )

        self.assertIn(
            "Suspicious language",
            evidence,
        )

        self.assertIn(
            "URLs extracted: 1",
            evidence,
        )

    def test_high_risk_fallback_is_cautious(self):
        analysis = {
            "risk_level": "High",
            "score": 70,
            "urls": [],
            "indicators": [],
        }

        fallback = build_default_risk_sentence(
            analysis
        )

        self.assertIn(
            "may represent phishing",
            fallback,
        )

        self.assertNotIn(
            "confirmed phishing",
            fallback,
        )


if __name__ == "__main__":
    unittest.main()
