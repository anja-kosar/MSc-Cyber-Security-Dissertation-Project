# ========== CUES.PY (BEGINNER-FRIENDLY) ==========
# This file contains a cue detection system for persuasive phrases in text.
# It is designed to find phrases that indicate urgency, authority, scarcity, fear of loss, etc.
# These cues are often used in phishing or scam messages to manipulate recipients.
# For each category, a list of phrases is kept, compiled into regex patterns, and matched against input text.
# The output is a dictionary of categories, each containing a dictionary of matched phrases and their counts.
# It also provides a function to summarize counts per category, which is sent to the outputs folder.

import re

# Below is a step-by-step implementation of the cue detection system.
# It contains a list of phrases for each category, for other files to use and look for.
CUE_LEXICON = {
    "authority": [
        "official notice", "account review team", "security team", "compliance team",
        "verified badge", "support team", "customer service", "help center",
        "administrator", "admin", "security", "support", "service", "notice"
    ],
    "urgency": [
        "urgent action required", "act now", "immediate action", "final notice",
        "expires soon", "deadline", "verify within 24 hours",
        "urgent", "immediately", "now", "today", "minutes", "hours", "24 hours"
    ],
    "scarcity": [
        "only a few left", "limited availability", "limited slots", "while supplies last",
        "limited", "last chance", "only today"
    ],
    "fear_loss": [
        "unusual activity detected", "unauthorised login", "unauthorized login",
        "your account is locked", "payment failed", "suspicious activity",
        "security alert", "fraud alert",
        "suspended", "suspension", "locked", "disabled", "restricted",
        "compromised", "violation", "failed", "failure", "alert", "warning"
    ],
    "consistency_commitment": [
        "confirm your identity", "verify your account", "update your details",
        "complete your profile", "continue to your account",
        "confirm", "verify", "update", "continue", "proceed", "submit", "resolve",
        "login", "sign in", "reset", "password", "identity", "account"
    ],
    "similarity_socialproof": [
        "people like you", "as recommended", "popular choice", "trending now",
        "recommended", "popular", "trending"
    ],
    "reward_reciprocity": [
        "claim your reward", "you have won", "exclusive offer", "congratulations",
        "reward", "bonus", "voucher", "gift", "prize"
    ],
    "brand_trust": [
        "amazon", "barclays", "facebook", "meta", "instagram", "mastercard", "netflix", "paypal",
        "apple", "microsoft", "google", "coinbase", "uphold", "telenet"
    ],
}

# Below builds the cue detection system in several steps:
# It compiles regex patterns for each phrase, then counts matches in input text.
def compile_patterns(lexicon):
    patterns = {}  # this will hold compiled regex patterns
    for category, phrases in lexicon.items():
        patterns[category] = []
        for phrase in phrases:
            # re.escape to treat special characters literally
            pattern_text = r"\b" + re.escape(phrase) + r"\b"
            compiled = re.compile(pattern_text, re.IGNORECASE)
            patterns[category].append((compiled, phrase))
    return patterns

PATTERNS = compile_patterns(CUE_LEXICON)

# Below counts occurrences of each phrase in the input text.
# Input: text string
# Output: { category: { phrase: count, ... }, ... }
def detect_cues(text):
    results = {}
    for category, plist in PATTERNS.items():
        # create inner dictionary for this category
        results[category] = {}
        for (regex_obj, phrase) in plist:
            # find all non-overlapping matches for this phrase
            count = 0
            for _ in regex_obj.finditer(text):
                count += 1
            if count > 0:
                results[category][phrase] = count
        # ensure the category exists even if no phrases matched
        if category not in results:
            results[category] = {}
    return results

# Below summarizes total counts per category.
# Input: output of detect_cues()
# Output: { category: total_count }
def summarize_counts(matches):
    totals = {}
    for category, phrase_counts in matches.items():
        total = 0
        for phrase, count in phrase_counts.items():
            total += count
        totals[category] = total
    return totals
