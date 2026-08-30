import ipaddress
import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)


SUSPICIOUS_PHRASES = {
    "urgent": 5,
    "immediately": 5,
    "verify your account": 10,
    "account suspended": 10,
    "account is suspended": 10,
    "password expires": 15,
    "password expired": 15,
    "your password has expired": 15,
    "change your password": 10,
    "current password will cease to work": 10,
    "unusual activity": 10,
    "click here": 5,
    "confirm your identity": 10,
    "payment failed": 10,
    "gift card": 10,
    "tax refund": 15,
    "refund request": 10,
    "eligible to receive": 10,
    "reactivate your account": 15,
    "re-activate your account": 15,
    "account services have expired": 15,
    "account services has expired": 15,
    "sign in and reactivate": 15,
}


DANGEROUS_EXTENSIONS = (
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".iso",
    ".img",
    ".zip",
)


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
}


BRAND_RULES = {
    "Microsoft": {
        "terms": (
            "microsoft",
            "outlook",
            "hotmail",
        ),
        "allowed_domains": (
            "microsoft.com",
            "microsoftonline.com",
            "office.com",
            "outlook.com",
            "live.com",
        ),
        "action_terms": (
            "password",
            "account",
            "sign in",
            "reactivate",
            "expired",
        ),
    },

    "HM Revenue & Customs": {
        "terms": (
            "hm revenue",
            "hmrc",
        ),
        "allowed_domains": (
            "gov.uk",
            "hmrc.gov.uk",
        ),
        "action_terms": (
            "tax refund",
            "refund request",
            "eligible to receive",
        ),
    },
}


def extract_urls(email_text: str) -> list[str]:
    """Extract and clean HTTP and HTTPS URLs."""

    return [
        url.rstrip(".,);]}>")
        for url in URL_PATTERN.findall(email_text)
    ]


def extract_header(email_text: str, header_name: str) -> str:
    """
    Extract a header while allowing indentation and a sender address
    continued onto the following line.
    """

    lines = email_text.splitlines()
    header_prefix = f"{header_name.lower()}:"

    for index, line in enumerate(lines):
        stripped_line = line.strip()

        if not stripped_line.lower().startswith(header_prefix):
            continue

        header_value = stripped_line.split(":", 1)[1].strip()

        if (
            header_name.lower() == "from"
            and "@" not in header_value
        ):
            for next_line in lines[index + 1:index + 3]:
                continuation = next_line.strip()

                if not continuation:
                    continue

                if EMAIL_PATTERN.search(continuation):
                    header_value = (
                        f"{header_value} {continuation}"
                    )

                break

        return header_value

    return ""


def extract_sender_domain(email_text: str) -> str:
    """Extract the sender domain from the From header."""

    from_header = extract_header(
        email_text,
        "From",
    )

    match = EMAIL_PATTERN.search(from_header)

    if match:
        return match.group(1).lower().rstrip(".")

    return ""


def domain_is_allowed(
    sender_domain: str,
    allowed_domains: tuple[str, ...],
) -> bool:
    """Check whether the sender uses an expected brand domain."""

    return any(
        sender_domain == allowed_domain
        or sender_domain.endswith(f".{allowed_domain}")
        for allowed_domain in allowed_domains
    )


def hostname_is_ip_address(hostname: str) -> bool:
    """Return True when a hostname is an IP address."""

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def add_indicator(
    indicators: list[dict],
    category: str,
    detail: str,
    points: int,
) -> int:
    """Add a transparent indicator and return its points."""

    indicators.append({
        "category": category,
        "detail": detail,
        "points": points,
    })

    return points


def analyze_email(email_text: str) -> dict:
    """Analyze email text using transparent detection rules."""

    indicators = []
    urls = extract_urls(email_text)
    lowered_text = email_text.lower()
    sender_domain = extract_sender_domain(email_text)
    score = 0

    for phrase, points in SUSPICIOUS_PHRASES.items():
        if phrase in lowered_text:
            score += add_indicator(
                indicators,
                "Suspicious language",
                f'Phrase detected: "{phrase}"',
                points,
            )

    for brand_name, rule in BRAND_RULES.items():
        brand_present = any(
            term in lowered_text
            for term in rule["terms"]
        )

        suspicious_action_present = any(
            term in lowered_text
            for term in rule["action_terms"]
        )

        sender_is_untrusted = (
            sender_domain
            and not domain_is_allowed(
                sender_domain,
                rule["allowed_domains"],
            )
        )

        if (
            brand_present
            and suspicious_action_present
            and sender_is_untrusted
        ):
            score += add_indicator(
                indicators,
                "Brand impersonation",
                (
                    f"{brand_name} language was used, but "
                    f"the sender domain is {sender_domain}"
                ),
                25,
            )

    for url in urls:
        parsed_url = urlparse(url)
        hostname = (
            parsed_url.hostname or ""
        ).lower()

        if parsed_url.scheme.lower() == "http":
            score += add_indicator(
                indicators,
                "Insecure URL",
                f"Unencrypted HTTP link: {url}",
                8,
            )

        if hostname in URL_SHORTENERS:
            score += add_indicator(
                indicators,
                "Shortened URL",
                (
                    "URL-shortening service detected: "
                    f"{hostname}"
                ),
                10,
            )

        if hostname_is_ip_address(hostname):
            score += add_indicator(
                indicators,
                "IP-based URL",
                (
                    "Link uses an IP address instead of "
                    f"a domain: {hostname}"
                ),
                15,
            )

        if "xn--" in hostname:
            score += add_indicator(
                indicators,
                "Punycode domain",
                (
                    "Possible internationalized lookalike "
                    f"domain: {hostname}"
                ),
                15,
            )

        if parsed_url.path.lower().endswith(
            DANGEROUS_EXTENSIONS
        ):
            score += add_indicator(
                indicators,
                "Risky file type",
                (
                    "Link points to a potentially dangerous "
                    f"file: {url}"
                ),
                20,
            )

    score = min(score, 100)

    if score >= 50:
        risk_level = "High"

    elif score >= 25:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    return {
        "risk_level": risk_level,
        "score": score,
        "sender_domain": sender_domain,
        "urls": urls,
        "indicators": indicators,
    }
