"""Historical matching by sequence similarity (contract 4).

Two technique sequences are compared after folding sub-techniques into their
parents and removing consecutive repeats.

  technique component = Jaccard overlap of the two technique sets
  temporal component  = 1 - edit distance / length of the longer sequence
  similarity          = W_TECHNIQUE * technique + W_TEMPORAL * temporal

The temporal component is about ORDER only: historical records carry no
timestamps, so time gaps between steps are not compared. mode="static" uses
the technique component alone (order ignored), which is what experiment E2
compares against.

Both components divide by the longer sequence (or the union), so the score
is for comparing COMPLETE attacks. An incident still in progress scores low
against its own, longer, reference, and very short historical records can
outrank it (measured in evaluation/results/m4_similarity.txt).

No embeddings and no learned weights; every score can be recomputed by hand.
"""

from .historical import historical, to_sequence

W_TECHNIQUE = 0.5
W_TEMPORAL = 0.5
TOP_K = 5


def jaccard(a, b):
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if a | b else 0.0


def edit_distance(a, b):
    """Levenshtein distance between two sequences."""
    previous = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        current = [i]
        for j, y in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (x != y)))
        previous = current
    return previous[-1]


def order_similarity(a, b):
    longest = max(len(a), len(b))
    return 1 - edit_distance(a, b) / longest if longest else 0.0


def similarity(a, b, mode="temporal"):
    """a, b: sequences of parent technique ids. Returns a value in [0, 1]."""
    if mode == "static":
        return jaccard(a, b)
    return W_TECHNIQUE * jaccard(a, b) + W_TEMPORAL * order_similarity(a, b)


def trajectory_ids(trajectory):
    return [step["id"] for step in trajectory["techniques"]]


def match_historical(trajectory, top_k=TOP_K, mode="temporal", sources=None, exclude=()):
    """Attack Trajectory (contract 3) -> Historical Match (contract 4).

    common_techniques lists the incident's own technique ids (sub-technique
    form kept) whose parent also occurs in the historical attack, in the order
    they occur in the incident. exclude: attack ids to leave out (evaluation).
    """
    original = trajectory_ids(trajectory)
    sequence = to_sequence(original)
    scored = []
    for record in historical(sources):
        if record["attack_id"] in exclude:
            continue
        score = similarity(sequence, record["sequence"], mode) if sequence else 0.0
        if score > 0:
            shared = set(sequence) & set(record["sequence"])
            common = list(dict.fromkeys(t for t in original if t.split(".")[0] in shared))
            scored.append((score, record["attack_id"], common))
    scored.sort(key=lambda s: (-s[0], s[1]))  # rank on the exact score, round only for output
    return {
        "incident_id": trajectory["incident_id"],
        "matches": [
            {"attack_id": attack_id, "similarity": round(score, 3), "common_techniques": common}
            for score, attack_id, common in scored[:max(top_k, 0)]
        ],
    }
