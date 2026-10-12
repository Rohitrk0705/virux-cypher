"""The two sets of incident trajectories every later evaluation runs on.

ground truth - the technique sequence the generator recorded for each of the
               24 incidents. Isolates the component under test from upstream
               errors.
pipeline     - what the label-free pipeline actually produces: incidents
               inferred from mapper-tagged events, techniques from the mapper,
               paired one-to-one with the true incidents for scoring.
"""

from knowledge_graph import config
from temporal import incidents

from . import incident_match


def ground_truth_trajectories():
    return [
        {"gt_id": t["incident_id"], "pattern": t["pattern"], "variant": t["variant"],
         "incident_id": t["incident_id"], "techniques": list(t["techniques"])}
        for t in incident_match.load_truth()
    ]


def pipeline_trajectories(method=config.METHOD_MAPPER, window_minutes=None):
    """One entry per true incident; techniques is None when the pipeline
    produced no incident overlapping it."""
    truth = incident_match.load_truth()
    ts, _ = incident_match.load_event_index()
    mapped = incident_match.load_mapped()
    inferred = incidents.infer_incidents(method, window_minutes)
    clusters = {c["incident_id"]: set(c["event_ids"]) for c in inferred}
    pairing = incident_match.assign(truth, clusters)
    out = []
    for t in truth:
        match = pairing.get(t["incident_id"])
        out.append({
            "gt_id": t["incident_id"], "pattern": t["pattern"], "variant": t["variant"],
            "incident_id": match,
            "techniques": incident_match.technique_sequence(clusters[match], ts, mapped) if match else None,
        })
    return out


def benign_pipeline_trajectories(method=config.METHOD_MAPPER, window_minutes=None):
    """Inferred incidents that contain no attack event at all (false incidents),
    with the trajectory the mapper gives them."""
    truth = incident_match.load_truth()
    attack = {e for t in truth for e in t["event_ids"]}
    ts, _ = incident_match.load_event_index()
    mapped = incident_match.load_mapped()
    return [
        {"gt_id": None, "pattern": None, "variant": None, "incident_id": c["incident_id"],
         "techniques": incident_match.technique_sequence(c["event_ids"], ts, mapped)}
        for c in incidents.infer_incidents(method, window_minutes)
        if not attack & set(c["event_ids"])
    ]


def as_contract_3(entry):
    """Trajectory dict accepted by match_historical / predict_next. Timestamps
    are not needed by either, so they are left empty here."""
    return {"incident_id": entry["incident_id"],
            "techniques": [{"id": t, "timestamp": ""} for t in entry["techniques"]]}
