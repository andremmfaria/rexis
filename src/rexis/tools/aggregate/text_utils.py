from collections import Counter
from typing import Iterable, List, Optional

from rexis.utils.constants import (
    CATEGORIES,
    CATEGORY_TOKEN_SPLIT_RE,
    CATEGORY_TOKENS,
    FAMILY_TO_CATEGORY,
    GENERIC_CATEGORY_SKIP_TOKENS,
)


def tokens(text: str) -> List[str]:
    return [
        t for t in CATEGORY_TOKEN_SPLIT_RE.split(text.lower()) if len(t) >= 3 and not t.isdigit()
    ]


def infer_category_from_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    ts = [t for t in tokens(text) if t not in GENERIC_CATEGORY_SKIP_TOKENS]
    if not ts:
        return None
    for t in ts:
        if t in FAMILY_TO_CATEGORY:
            return FAMILY_TO_CATEGORY[t]
    for cat, keys in CATEGORY_TOKENS.items():
        if any(t in keys for t in ts):
            return cat
    for t in ts:
        if t in CATEGORIES:
            return t
    return None


def infer_category_from_many_texts(texts: List[str]) -> Optional[str]:
    votes: List[str] = []
    for s in texts:
        c = infer_category_from_text(s)
        if c:
            votes.append(c)
    if not votes:
        return None
    return Counter(votes).most_common(1)[0][0]


def first_category_in_list(xs: Iterable[str] | None) -> Optional[str]:
    if not xs:
        return None
    for x in xs:
        t = str(x).strip().lower()
        if t in CATEGORIES:
            return t
    return None
