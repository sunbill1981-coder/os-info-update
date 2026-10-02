from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Set
from urllib.parse import urlsplit

from .assessment import action_priority, alert_level
from .model import Event, stable_hash


def derive_correlation_key(event: Event) -> str:
    identifiers: List[str] = []
    for name in ("kb", "build", "cve", "advisory"):
        value = event.identifiers.get(name, [])
        identifiers.extend(value if isinstance(value, list) else [str(value)])
    dimensions = event.change_kinds + event.affected_workflows + event.symptoms + event.preconditions
    if not identifiers or len(dimensions) < 2:
        return ""
    return "risk:" + stable_hash([sorted(set(identifiers)), sorted(set(dimensions))])[:24]


def correlate_events(events: Iterable[Event]) -> None:
    event_list = list(events)
    for event in event_list:
        derived = derive_correlation_key(event)
        if derived:
            event.correlation_keys = sorted(set(event.correlation_keys + [derived]))
    sources: Dict[str, Set[str]] = defaultdict(set)
    for event in event_list:
        review = event.evidence_review
        if review:
            origin = str(review.get("original_url") or event.source_url)
            if origin != event.source_url:
                # Reposts are links to evidence, never extra independent observations.
                continue
            source_identity = "origin:" + origin.casefold()
            if review.get("source_kind") == "community":
                if review.get("independent_observation") and review.get("author"):
                    # Two reports by the same author on one platform count once.
                    source_identity = "observer:{}:{}".format(urlsplit(origin).hostname, str(review["author"]).casefold())
                else:
                    # Anonymous/unverified reports never add another observer to a
                    # verified report on the same risk, even on a different site.
                    continue
            else:
                # Separate pages by the same publisher do not make independent confirmations.
                source_identity = "publisher:" + str(urlsplit(origin).hostname)
        else:
            source_identity = f"{event.publisher.casefold()}|{event.source_id.casefold()}"
        for key in set(event.correlation_keys):
            sources[key].add(source_identity)
    for event in event_list:
        observed = max(1, max((len(sources[key]) for key in event.correlation_keys), default=0))
        event.corroboration_count = observed
        event.action_priority = action_priority(event.risk_score, event.environment_relevance, event.confidence, event.threat_urgency)
        event.alert_level = alert_level(event)
