"""What the SOC knows about the monitored environment (asset inventory).

This is configuration a real deployment would take from its CMDB and identity
system. It contains no information about which events are attacks.
"""

from datetime import datetime, timezone

INTERNAL_PREFIX = "10."

# Server hosts: they do not browse the internet on their own.
SERVERS = ["SRV-DC01", "SRV-DB01", "SRV-FILE01", "SRV-MAIL01"]

# Administrator accounts and the workstations they are expected to work from.
ADMIN_WORKSTATIONS = {"admin_lee": {"device": "WS-07", "ip": "10.0.0.17"}}

# Service accounts and the hosts they run on.
SERVICE_ACCOUNTS = {"svc_backup": {"device": "SRV-FILE01", "ip": "10.0.0.4"}}


# Local business hours, weekdays only. Log timestamps are treated as local time.
BUSINESS_HOURS = (7, 19)


def business_hours(epoch_seconds):
    moment = datetime.fromtimestamp(epoch_seconds, timezone.utc)
    return moment.weekday() < 5 and BUSINESS_HOURS[0] <= moment.hour < BUSINESS_HOURS[1]


def is_internal(ip):
    return ip is not None and ip.startswith(INTERNAL_PREFIX)
