import json
import sys

from . import investigate

if len(sys.argv) != 2:
    sys.exit("usage: python -m agents.investigation_agent <incident_id>")
try:
    print(json.dumps(investigate(sys.argv[1]), indent=2))
except LookupError as exc:
    sys.exit(str(exc))
