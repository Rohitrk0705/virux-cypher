"""Shared settings for the graph, temporal and evaluation layers."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "viruxcypher")

PROCESSED_DIR = ROOT / "data" / "processed"
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
DEFAULT_METHOD = METHOD_HEURISTIC
DEFAULT_TECHNIQUE_SOURCE = SOURCE_GROUND_TRUTH
