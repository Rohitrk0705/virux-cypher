"""What the SOC knows about a monitored environment (asset inventory).

This is configuration a real deployment would take from its CMDB and identity
system. It contains no information about which events are attacks.

BANK is the fictional bank of the synthetic benchmark. PANDALAB is the OTRF lab
the real datasets were captured in; for it we know only what the data itself
shows (its two host subnets), so it has no servers, no administrator list and
no business hours.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class Environment:
    name: str
    # Address prefixes of the organisation's own network. Anything else is external.
    internal_prefixes: tuple
    # Server hosts: they do not browse the internet on their own.
    servers: frozenset = frozenset()
    # Administrator accounts and the workstation each is expected to work from.
    admin_workstations: dict = field(default_factory=dict)
    # Service accounts and the host each runs on.
    service_accounts: dict = field(default_factory=dict)
    # Built-in operating-system accounts; their housekeeping is never mapped by the tool rules.
    system_accounts: frozenset = frozenset()
    # Local business hours on weekdays as (start hour, end hour), or None when unknown.
    # Log timestamps are treated as local time.
    business_hours: tuple | None = None

    def is_internal(self, ip):
        return ip is not None and str(ip).lower().startswith(self.internal_prefixes)

    def in_business_hours(self, epoch_seconds):
        """False only when the hours are known and this moment is outside them."""
        if self.business_hours is None:
            return True
        moment = datetime.fromtimestamp(epoch_seconds, timezone.utc)
        return moment.weekday() < 5 and self.business_hours[0] <= moment.hour < self.business_hours[1]


BANK = Environment(
    name="bank (synthetic benchmark)",
    internal_prefixes=("10.",),
    servers=frozenset({"SRV-DC01", "SRV-DB01", "SRV-FILE01", "SRV-MAIL01"}),
    admin_workstations={"admin_lee": {"device": "WS-07", "ip": "10.0.0.17"}},
    service_accounts={"svc_backup": {"device": "SRV-FILE01", "ip": "10.0.0.4"}},
    system_accounts=frozenset(),
    business_hours=(7, 19),
)

PANDALAB = Environment(
    name="pandalab (OTRF Security-Datasets LSASS campaigns)",
    # host subnets seen in the captures, plus multicast and IPv6 link-local noise
    internal_prefixes=("192.168.", "224.", "239.", "255.", "fe80:", "ff02:", "127.", "::1"),
    system_accounts=frozenset({"system", "network service", "local service"}),
    business_hours=None,
)

DMEVALS = Environment(
    name="dmevals (OTRF apt29 day 1, ATT&CK Evaluations round 2 emulation)",
    # the four hosts' own subnets as seen in the capture, plus multicast and link-local noise
    internal_prefixes=("10.0.", "224.", "239.", "255.", "fe80:", "ff02:", "127.", "::1"),
    system_accounts=frozenset({"system", "network service", "local service"}),
    business_hours=None,
)
