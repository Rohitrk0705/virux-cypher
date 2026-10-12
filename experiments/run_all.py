"""Run E1, E2 and E3 and write experiments/results/.

  python -m experiments.run_all
"""

from . import e1_historical, e2_temporal, e3_discrimination


def main():
    for module in (e1_historical, e2_temporal, e3_discrimination):
        module.main()
        print("\n" + "=" * 100 + "\n")


if __name__ == "__main__":
    main()
