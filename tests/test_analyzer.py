import unittest

from analyzer import analyze_email


class TestPhishingAnalyzer(unittest.TestCase):

    def test_legitimate_email_is_low_risk(self):
        email_text = """
        From: HR Department <hr@example.test>
        Subject: Updated holiday schedule

        The updated holiday schedule is available internally.
        Contact Human Resources with any questions.
        """

        result = analyze_email(email_text)

        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["urls"], [])
        self.assertEqual(result["indicators"], [])

    def test_suspicious_email_is_medium_risk(self):
        email_text = """
        From: Support <support@example.test>
        Subject: Unusual activity detected

        Confirm your identity. Click here:
        https://account-review.example.test/login
        """

        result = analyze_email(email_text)

        self.assertEqual(result["risk_level"], "Medium")
        self.assertEqual(result["score"], 25)
        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(len(result["indicators"]), 3)

    def test_phishing_simulation_is_high_risk(self):
        email_text = """
        From: Security <security@example.test>
        Subject: Urgent account verification

        URGENT: Verify your account immediately.

        Click here:
        http://192.0.2.10/update.exe
        """

        result = analyze_email(email_text)

        self.assertEqual(result["risk_level"], "High")
        self.assertEqual(result["score"], 68)
        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(len(result["indicators"]), 7)

    def test_hmrc_refund_impersonation_is_high_risk(self):
        email_text = """
        From: Sender <sender@hotmail.example.test>
        Subject: HMRC Tax Refund

        HM Revenue & Customs has determined that you are
        eligible to receive a tax refund.

        Submit the refund request:
        http://hmrc-refund.example.test/claim
        """

        result = analyze_email(email_text)

        self.assertEqual(result["risk_level"], "High")
        self.assertGreaterEqual(result["score"], 50)

        categories = {
            item["category"]
            for item in result["indicators"]
        }

        self.assertIn("Brand impersonation", categories)
        self.assertIn("Insecure URL", categories)

    def test_password_expiration_impersonation_is_high_risk(self):
        email_text = """
        From: Microsoft Outlook
        <msoutlook94@service-outlook.example.test>
        Subject: Your Password Has Expired

        Your password has expired.
        Your current password will cease to work shortly.

        Change your password immediately:
        http://service-outlook.example.test/reset.html
        """

        result = analyze_email(email_text)

        self.assertEqual(result["risk_level"], "High")
        self.assertGreaterEqual(result["score"], 50)

        categories = {
            item["category"]
            for item in result["indicators"]
        }

        self.assertIn("Brand impersonation", categories)

    def test_outlook_reactivation_impersonation_is_high_risk(self):
        email_text = """
        From: Microsoft Account Team
        <account-team@outlook-support.example.test>
        Subject: Reactivate Your Outlook Account

        Your Hotmail account services have expired.

        Sign in and reactivate your account:
        https://account-live.example.test/reactivate
        """

        result = analyze_email(email_text)

        self.assertEqual(result["risk_level"], "High")
        self.assertGreaterEqual(result["score"], 50)

        categories = {
            item["category"]
            for item in result["indicators"]
        }

        self.assertIn("Brand impersonation", categories)

    def test_score_cannot_exceed_100(self):
        email_text = """
        From: Microsoft Support
        <support@malicious.example.test>
        Subject: Urgent account problem

        URGENT. Verify your account immediately.
        Your account is suspended due to unusual activity.
        Confirm your identity because payment failed.
        Purchase a gift card and click here:
        http://192.0.2.10/malware.exe
        """

        result = analyze_email(email_text)

        self.assertEqual(result["score"], 100)
        self.assertEqual(result["risk_level"], "High")


if __name__ == "__main__":
    unittest.main()
