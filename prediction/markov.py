"""Baseline next-step prediction: Markov transition probabilities (contract 5).

The model is a table of counts over historical technique sequences:

  P(next | last k steps) = count(last k steps -> next) / count(last k steps)

"Ended there" is counted as an outcome too, so a step that only ever closes
historical sequences is known to the model and predicts nothing rather than
being treated as unseen. The model tries the longest context first
(k = MAX_ORDER) and backs off to a shorter one when that context was seen
fewer than MIN_SUPPORT times. If the last step never occurs in the history it
falls back to how often each technique follows anything at all, and for an
empty trajectory to how often each technique starts a sequence.

No machine learning, no embeddings; every probability is a ratio of two counts
that the evidence list states. Sequences are parent technique ids with
consecutive repeats removed, so the predictions are parent ids too.

The default model is trained on the hand-specified historical sequences only.
MITRE ATT&CK group records are NOT used for prediction: their order is
inferred from tactic position and technique id, so their "transitions" are an
artefact of sorting, and measured accuracy with them is zero alone and lower
when pooled (evaluation/results/m5_prediction.txt).
"""

from collections import Counter, defaultdict

from .historical import SOURCE_CURATED, historical, to_sequence
from .similarity import match_historical, trajectory_ids

MAX_ORDER = 2
MIN_SUPPORT = 2
TOP_K = 5
END = "<end>"


class MarkovPredictor:
    def __init__(self, sequences, max_order=MAX_ORDER, min_support=MIN_SUPPORT, description="historical"):
        self.max_order = max_order
        self.min_support = min_support
        self.description = description
        self.n_sequences = 0
        # counts[k][context tuple] = Counter(next technique or END)
        self.counts = {k: defaultdict(Counter) for k in range(1, max_order + 1)}
        # containing[k][context tuple] = number of sequences containing that context
        self.containing = {k: Counter() for k in range(1, max_order + 1)}
        self.any_next = Counter()   # technique -> times it follows another step
        self.starts = Counter()     # technique -> times it opens a sequence
        for sequence in sequences:
            self._add(to_sequence(sequence))

    def _add(self, seq):
        if not seq:
            return
        self.n_sequences += 1
        self.starts[seq[0]] += 1
        for technique in seq[1:]:
            self.any_next[technique] += 1
        for k in range(1, self.max_order + 1):
            seen = set()
            for i in range(k, len(seq) + 1):
                context = tuple(seq[i - k:i])
                self.counts[k][context][seq[i] if i < len(seq) else END] += 1
                seen.add(context)
            for context in seen:
                self.containing[k][context] += 1

    def lookup(self, path):
        """Which counts answer this path. Returns a dict:
        kind       'context' | 'start' | 'unseen' | 'empty_history'
        outcomes   Counter(next technique or END)
        total      sum of outcomes
        order, context, sequences, skipped
        """
        path = to_sequence(path)
        if not self.n_sequences:
            return {"kind": "empty_history", "outcomes": Counter(), "total": 0, "order": 0,
                    "context": (), "sequences": 0, "skipped": []}
        if not path:
            return {"kind": "start", "outcomes": self.starts, "total": self.n_sequences, "order": 0,
                    "context": (), "sequences": self.n_sequences, "skipped": []}
        skipped = []
        for k in range(min(self.max_order, len(path)), 0, -1):
            context = tuple(path[-k:])
            outcomes = self.counts[k].get(context)
            total = sum(outcomes.values()) if outcomes else 0
            if total >= (self.min_support if k > 1 else 1):
                return {"kind": "context", "outcomes": outcomes, "total": total, "order": k,
                        "context": context, "sequences": self.containing[k][context], "skipped": skipped}
            skipped.append((k, context, total))
        return {"kind": "unseen", "outcomes": self.any_next, "total": sum(self.any_next.values()),
                "order": 0, "context": (path[-1],), "sequences": 0, "skipped": skipped}

    def rank(self, path):
        """Ranked [(technique, probability)] for a path, plus the lookup used.
        'Ended there' is part of the denominator but is not a prediction, so the
        probabilities can sum to less than 1."""
        info = self.lookup(path)
        ranked = [(t, c / info["total"])
                  for t, c in sorted(info["outcomes"].items(), key=lambda kv: (-kv[1], kv[0]))
                  if t != END]
        return ranked, info

    def evidence(self, info):
        """Statements of the counts behind a prediction; each is literally true."""
        n, kind, outcomes = self.n_sequences, info["kind"], info["outcomes"]
        continuations = [(t, c) for t, c in sorted(outcomes.items(), key=lambda kv: (-kv[1], kv[0])) if t != END]
        if kind == "empty_history":
            return ["no historical trajectories are available, so nothing can be predicted"]
        if kind == "start":
            top, count = continuations[0]
            return [f"the trajectory is empty; {count} of {n} {self.description} trajectories start with {top}"]
        if kind == "unseen":
            lines = [f"the last step {info['context'][0]} does not occur in any of the {n} "
                     f"{self.description} trajectories"]
            if continuations:
                top, count = continuations[0]
                lines.append(f"fell back to overall frequency: {top} is the next step in {count} of "
                             f"{info['total']} historical transitions")
            return lines
        steps = " > ".join(info["context"])
        lines = [f"the last {info['order']} step(s) {steps} occur {info['total']} time(s) "
                 f"in {info['sequences']} of {n} {self.description} trajectories"]
        if continuations:
            top, count = continuations[0]
            lines.append(f"{count} of those {info['total']} were followed by {top}")
        ended = outcomes.get(END, 0)
        if ended:
            lines.append(f"{ended} of those {info['total']} were the last step of their trajectory")
        if not continuations:
            lines.append("no continuation has been observed after this point, so no next step is predicted")
        for k, context, total in info["skipped"]:
            lines.append(f"the longer context {' > '.join(context)} was seen {total} time(s), "
                         f"fewer than the {self.min_support} required, so it was not used")
        return lines


_default = None


def default_predictor():
    """Trained on the hand-specified historical sequences (see module docstring)."""
    global _default
    if _default is None:
        _default = MarkovPredictor((r["sequence"] for r in historical([SOURCE_CURATED])),
                                   description="hand-specified historical")
    return _default


def predict_next(trajectory, predictor=None, top_k=TOP_K):
    """Attack Trajectory (contract 3) -> Prediction (contract 5).

    With the default predictor the evidence also names the closest historical
    attack; that line is informational and plays no part in the probabilities.
    An empty predictions list means the history gives no basis for a prediction.
    """
    use_default = predictor is None
    predictor = predictor or default_predictor()
    ranked, info = predictor.rank(trajectory_ids(trajectory))
    evidence = predictor.evidence(info)

    if info["kind"] == "context" and ranked:
        evidence.append("the prediction uses the order of the observed steps")
    if use_default:
        matches = match_historical(trajectory, top_k=1)["matches"]
        if matches:
            evidence.append(f"closest historical attack overall is {matches[0]['attack_id']} "
                            f"(similarity {matches[0]['similarity']}); not used for the probabilities")

    return {
        "incident_id": trajectory["incident_id"],
        "predictions": [{"technique_id": t, "probability": round(p, 3)} for t, p in ranked[:max(top_k, 0)]],
        "evidence": evidence,
    }
