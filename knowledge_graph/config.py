"""Shared settings for the graph, temporal and evaluation layers."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "viruxcypher")

# Which dataset the pipeline reads. Empty = the default 24-incident benchmark in
# data/processed/. VIRUX_DATASET=graded selects data/processed/graded/ (M10).
DATASET = os.getenv("VIRUX_DATASET", "")
PROCESSED_DIR = ROOT / "data" / "processed" / DATASET
EVENTS_FILE = PROCESSED_DIR / "events.json"
LABELS_FILE = PROCESSED_DIR / "labels.json"
INCIDENTS_FILE = PROCESSED_DIR / "incidents.json"  # evaluation ground truth only
MAPPED_FILE = PROCESSED_DIR / "mapped.json"        # output of core.attack_mapper

# Addresses inside this prefix are the bank's own network.
INTERNAL_PREFIX = "10."

# --- incident inference -----------------------------------------------------
# How incident candidates are selected. See temporal/incidents.py.
METHOD_HEURISTIC = "heuristic"  # label-free event-type rules
METHOD_LABELS = "labels"        # ground-truth labelled events (optimistic upper bound)
METHOD_MAPPER = "mapper"        # events the rule-based ATT&CK mapper mapped

# Where an Event's MAPS_TO edge came from.
SOURCE_GROUND_TRUTH = "ground_truth"
SOURCE_MAPPER = "mapper"

WINDOW_MINUTES = 30
SWEEP_WINDOWS = [5, 15, 30, 60, 120]
MIN_INCIDENT_EVENTS = 2

# A Device or IP used by this many distinct users is shared infrastructure
# (mail server, file server, a popular website) and is not evidence that two
# events belong together.
HUB_USERS = 4

# Everyday business applications; running one is not security-relevant on its
# own. Used only by the label-free heuristic filter.
ROUTINE_PROCESSES = [
    "outlook.exe", "excel.exe", "winword.exe", "chrome.exe",
    "teams.exe", "bankcore.exe", "notepad.exe",
]

# What the rest of the system (trajectory extraction, agent tools, API) reads.
# Both are label-free: incidents are grouped from the events the rule-based
# mapper tagged, and techniques come from the mapper. Ground truth is only ever
# an explicit opt-in for evaluation.
DEFAULT_METHOD = METHOD_MAPPER
DEFAULT_TECHNIQUE_SOURCE = SOURCE_MAPPER
