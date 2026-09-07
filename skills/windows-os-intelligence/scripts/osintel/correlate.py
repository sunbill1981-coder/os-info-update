from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Set

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
        source_identity = f"{event.publisher.casefold()}|{event.source_id.casefold()}"
        for key in set(event.correlation_keys):
            sources[key].add(source_identity)
    for event in event_list:
        observed = max((len(sources[key]) for key in event.correlation_keys), default=1)
        event.corroboration_count = max(event.corroboration_count, observed)
        event.action_priority = action_priority(event.risk_score, event.environment_relevance, event.confidence)
        event.alert_level = alert_level(event)
