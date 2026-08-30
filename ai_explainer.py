import os
import re
import subprocess
import textwrap


MODEL_NAME = "qwen2.5:1.5b"

ANSI_ESCAPE_PATTERN = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)

CONTROL_CHARACTER_PATTERN = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f]"
)

WORD_PATTERN = re.compile(
    r"[A-Za-z]+"
)


def clean_terminal_output(output: str) -> str:
    """Remove terminal formatting and control characters."""

    cleaned_output = ANSI_ESCAPE_PATTERN.sub(
        "",
        output,
    )

    cleaned_output = cleaned_output.replace(
        "\r",
        " ",
    )

    cleaned_output = CONTROL_CHARACTER_PATTERN.sub(
        "",
        cleaned_output,
    )

    return " ".join(
        cleaned_output.split()
    )


def run_ollama(
    prompt: str,
    timeout_seconds: int,
) -> str:
    """Run Ollama locally without invoking a shell."""

    command_environment = os.environ.copy()
    command_environment["OLLAMA_KEEP_ALIVE"] = "30m"

    completed_process = subprocess.run(
        [
            "ollama",
            "run",
            MODEL_NAME,
            prompt,
        ],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=True,
        env=command_environment,
    )

    return clean_terminal_output(
        completed_process.stdout
    )


def shorten_sentence(
    sentence: str,
    width: int = 220,
) -> str:
    """Limit excessive output without cutting words."""

    return textwrap.shorten(
        sentence,
        width=width,
        placeholder="...",
    )


def has_repetitive_words(sentence: str) -> bool:
    """Detect adjacent duplicate or malformed related words."""

    words = [
        word.lower()
        for word in WORD_PATTERN.findall(sentence)
    ]

    for first_word, second_word in zip(
        words,
        words[1:],
    ):
        if first_word == second_word:
            return True

        shorter_length = min(
            len(first_word),
            len(second_word),
        )

        if shorter_length < 3:
            continue

        common_prefix_length = 0

        for first_character, second_character in zip(
            first_word,
            second_word,
        ):
            if first_character != second_character:
                break

            common_prefix_length += 1

        if common_prefix_length >= 3:
            return True

    return False


def has_invalid_single_letter_word(sentence: str) -> bool:
    """
    Reject unexpected one-letter fragments.

    Valid English one-letter words are limited to A and I.
    """

    words = WORD_PATTERN.findall(sentence)

    return any(
        len(word) == 1
        and word.lower() not in {"a", "i"}
        for word in words
    )


def build_evidence_sentence(analysis: dict) -> str:
    """Build an exact statement from verified evidence."""

    categories = sorted({
        item["category"]
        for item in analysis.get("indicators", [])
    })

    url_count = len(
        analysis.get("urls", [])
    )

    if categories:
        return (
            "The assessment detected "
            + ", ".join(categories)
            + f". URLs extracted: {url_count}."
        )

    return (
        "No configured suspicious indicators were detected. "
        f"URLs extracted: {url_count}."
    )


def build_default_risk_sentence(analysis: dict) -> str:
    """Provide a safe fallback based on verified risk level."""

    risk_level = analysis.get(
        "risk_level",
        "Unknown",
    )

    if risk_level == "High":
        return (
            "The combined indicators may represent phishing, "
            "credential theft, malware delivery, or fraud."
        )

    if risk_level == "Medium":
        return (
            "The suspicious indicators require further review "
            "before the email can be considered trustworthy."
        )

    return (
        "The configured rules found limited phishing evidence, "
        "but this does not prove the email is safe."
    )


def ai_sentence_is_acceptable(sentence: str) -> bool:
    """Reject malformed, unsupported, or overconfident output."""

    if not sentence:
        return False

    lowered_sentence = sentence.lower()

    rejected_phrases = (
        "confirmed phishing",
        "definitely phishing",
        "multiple urls",
        "multiple links",
        "evidence:",
        "validation required:",
    )

    if any(
        phrase in lowered_sentence
        for phrase in rejected_phrases
    ):
        return False

    if len(WORD_PATTERN.findall(sentence)) > 35:
        return False

    if has_repetitive_words(sentence):
        return False

    if has_invalid_single_letter_word(sentence):
        return False

    return True


def request_ai_risk_sentence(
    analysis: dict,
) -> str | None:
    """Ask AI only to explain potential security impact."""

    categories = sorted({
        item["category"]
        for item in analysis.get("indicators", [])
    })

    category_text = (
        ", ".join(categories)
        if categories
        else "No configured suspicious indicators"
    )

    prompt = f"""
Write one clear sentence explaining the potential security impact.

Risk level: {analysis['risk_level']}
Risk score: {analysis['score']}/100
Evidence categories: {category_text}

Rules:
- Use no more than 25 words.
- Do not discuss URL quantities.
- Do not claim phishing is confirmed.
- Do not repeat words or phrases.
- Do not include headings, labels, bullets, or extra text.
"""

    for timeout_seconds in (
        120,
        180,
    ):
        try:
            output = run_ollama(
                prompt,
                timeout_seconds,
            )

            output = shorten_sentence(
                output.lstrip("-* ")
            )

            if ai_sentence_is_acceptable(
                output
            ):
                return output

        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            FileNotFoundError,
        ):
            continue

    return None


def explain_analysis(analysis: dict) -> str:
    """Combine verified evidence, guarded AI, and validation."""

    evidence_sentence = build_evidence_sentence(
        analysis
    )

    risk_sentence = request_ai_risk_sentence(
        analysis
    )

    if risk_sentence is None:
        risk_sentence = build_default_risk_sentence(
            analysis
        )

    return "\n".join([
        f"- Evidence: {evidence_sentence}",
        f"- Potential risk: {risk_sentence}",
        (
            "- Validation required: A human analyst must "
            "confirm the classification and supporting evidence."
        ),
    ])
