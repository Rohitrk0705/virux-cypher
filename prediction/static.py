"""Order-free comparison predictor for experiment E2 ("static KG").

It knows which techniques occur together in historical attacks but not in
which order. A candidate next technique is scored by the historical attacks
that contain it, each weighted by how much of the current path that attack
also contains. Techniques already in the path are not proposed.
"""

from collections import Counter

from .historical import to_sequence


class StaticPredictor:
    def __init__(self, sequences):
        self.sets = [set(to_sequence(s)) for s in sequences]
        self.n_sequences = len(self.sets)

    def rank(self, path):
        """An empty path has no co-occurring techniques, so nothing is proposed."""
        seen = set(to_sequence(path))
        scores = Counter()
        for members in self.sets:
            overlap = len(seen & members) / len(seen) if seen else 0.0
            if overlap:
                for t in members - seen:
                    scores[t] += overlap
        total = sum(scores.values())
        ranked = [(t, s / total) for t, s in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))]
        return ranked, {"kind": "static"}
