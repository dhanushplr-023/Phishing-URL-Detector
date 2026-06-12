import re
from urllib.parse import urlparse


# ==========================================
# SUSPICIOUS KEYWORDS
# ==========================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "secure",
    "update",
    "account",
    "bank",
    "wallet",
    "paypal",
    "confirm",
    "password",
    "reset",
    "recover",
    "authenticate"
]


# ==========================================
# SUSPICIOUS TLDs
# ==========================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".click",
    ".work",
    ".buzz"
]


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def is_ip_address(hostname):
    """
    Detect if hostname is an IP address
    """

    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

    return bool(
        re.match(pattern, hostname)
    )


def count_subdomains(hostname):
    """
    Count subdomains
    """

    return len(hostname.split("."))


# ==========================================
# MAIN ANALYZER
# ==========================================

def analyze_url(url):

    score = 0
    warnings = []

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname or ""

        path = parsed.path.lower()

        # ==================================
        # HTTPS CHECK
        # ==================================

        if parsed.scheme != "https":

            score += 20

            warnings.append(
                "Website is not using HTTPS"
            )

        # ==================================
        # SUSPICIOUS KEYWORDS
        # ==================================

        lower_url = url.lower()

        for keyword in SUSPICIOUS_KEYWORDS:

            if keyword in lower_url:

                score += 8

                warnings.append(
                    f"Suspicious keyword detected: {keyword}"
                )

        # ==================================
        # IP ADDRESS CHECK
        # ==================================

        if is_ip_address(hostname):

            score += 25

            warnings.append(
                "Uses IP address instead of domain name"
            )

        # ==================================
        # LONG URL CHECK
        # ==================================

        if len(url) > 75:

            score += 15

            warnings.append(
                "Unusually long URL"
            )

        # ==================================
        # @ SYMBOL CHECK
        # ==================================

        if "@" in url:

            score += 15

            warnings.append(
                "Contains @ symbol"
            )

        # ==================================
        # TOO MANY SUBDOMAINS
        # ==================================

        if count_subdomains(hostname) > 4:

            score += 15

            warnings.append(
                "Too many subdomains"
            )

        # ==================================
        # SUSPICIOUS TLD CHECK
        # ==================================

        for tld in SUSPICIOUS_TLDS:

            if hostname.endswith(tld):

                score += 10

                warnings.append(
                    f"Suspicious TLD detected ({tld})"
                )

        # ==================================
        # EXCESSIVE HYPHENS
        # ==================================

        if hostname.count("-") >= 3:

            score += 10

            warnings.append(
                "Too many hyphens in domain"
            )

        # ==================================
        # EXCESSIVE SPECIAL CHARACTERS
        # ==================================

        special_chars = len(
            re.findall(r"[@#$%^&*]", url)
        )

        if special_chars >= 2:

            score += 10

            warnings.append(
                "Excessive special characters"
            )

        # ==================================
        # DOUBLE SLASH IN PATH
        # ==================================

        if "//" in path:

            score += 5

            warnings.append(
                "Suspicious path structure"
            )

        # ==================================
        # LIMIT SCORE
        # ==================================

        score = min(score, 100)

        # ==================================
        # STATUS
        # ==================================

        if score >= 60:
            status = "DANGER"

        elif score >= 30:
            status = "WARNING"

        else:
            status = "SAFE"

        # ==================================
        # RETURN RESULT
        # ==================================

        return {
            "url": url,
            "score": score,
            "status": status,
            "warnings": warnings,
            "checks_performed": 8
        }

    except Exception as error:

        return {
            "url": url,
            "score": 100,
            "status": "DANGER",
            "warnings": [
                f"Analysis error: {str(error)}"
            ],
            "checks_performed": 0
        }