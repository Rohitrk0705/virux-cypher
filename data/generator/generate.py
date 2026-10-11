"""Synthetic labelled-log generator (skeleton).

Emits normal activity + injected attack sequences where the ground-truth
ATT&CK technique of every event is known. This is the project's primary dataset.

TODO:
  - define a fictional bank environment (hosts, users)
  - emit benign baseline events
  - inject labelled attack trajectories (e.g. T1078 -> T1059 -> T1068 -> T1021)
  - write Normalized Events (contract 1) + a ground-truth labels file
"""

if __name__ == "__main__":
    print("TODO: generate labelled synthetic logs")
