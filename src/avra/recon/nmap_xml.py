"""Parse nmap XML (``-oX``) into typed results (ADR 0003, M6.4).

The XML comes back from the lab, so it is treated as untrusted input:
parsed with ``defusedxml`` (no entity expansion, no external entities),
size-capped, and only the fields we need are read. Anything unexpected is
a ``NmapXmlError`` — never a partial, silently-wrong result.

A parsed port state is an *observation* by a tool, not a finding: nothing
here sets any finding status (CLAUDE.md "a suspected vulnerability is not a
confirmed one").
"""

from __future__ import annotations

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring
from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_XML_CHARS = 1_000_000


class NmapXmlError(Exception):
    """The XML is not a well-formed, safe, complete nmap report."""


class PortResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: str
    port: int = Field(ge=1, le=65535)
    state: str  # open | closed | filtered | unfiltered | open|filtered | closed|filtered
    reason: str = ""
    service: str = ""  # nmap's service label (may be only a port-table guess)
    service_method: str = ""  # how nmap decided: "table" (port-number lookup) | "probed"
    service_confidence: int | None = None  # nmap's conf, 0-10; None if absent

    @property
    def service_identified(self) -> bool:
        """True only when nmap actually probed the service (``method="probed"``),
        not when the label is a static port-number guess (``method="table"``).
        Under AVRA's fixed connect-scan flags (no ``-sV``) this is always False."""
        return self.service_method == "probed" and bool(self.service)


class HostResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    address: str
    status: str  # up | down | unknown
    ports: tuple[PortResult, ...] = ()


class NmapReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    nmap_version: str
    args: str
    hosts: tuple[HostResult, ...]
    exit_status: str  # nmap's own runstats verdict ("success" | "error")

    def port_states(self) -> dict[tuple[str, int], str]:
        return {(h.address, p.port): p.state for h in self.hosts for p in h.ports}


def parse_nmap_xml(xml: str) -> NmapReport:
    """Parse nmap -oX output. Any malformed or out-of-range content raises
    ``NmapXmlError`` (never a bare ValidationError: callers catch only this)."""
    try:
        return _parse(xml)
    except ValidationError as exc:  # e.g. portid 0 / 70000 (audit 2026-11-10)
        raise NmapXmlError(f"nmap report has invalid values ({exc.error_count()} "
                           "error(s))") from None


def _parse(xml: str) -> NmapReport:
    if not isinstance(xml, str) or not xml.strip():
        raise NmapXmlError("empty nmap output")
    if len(xml) > MAX_XML_CHARS:
        raise NmapXmlError("nmap output too large")
    try:
        root = fromstring(xml.encode("utf-8"))
    except (DefusedXmlException, ParseError) as exc:
        raise NmapXmlError(f"unsafe or malformed XML: {type(exc).__name__}") from None
    if root.tag != "nmaprun":
        raise NmapXmlError(f"not an nmap report (root <{root.tag}>)")
    finished = root.find("runstats/finished")
    if finished is None:
        raise NmapXmlError("incomplete nmap report (no runstats/finished)")

    hosts = []
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        status = host.find("status")
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            service = port.find("service")
            try:
                portid = int(port.get("portid", ""))
            except ValueError:
                raise NmapXmlError("port without a numeric portid") from None
            if state is None or not state.get("state"):
                raise NmapXmlError(f"port {portid} has no state")
            conf_raw = service.get("conf") if service is not None else None
            try:
                conf = int(conf_raw) if conf_raw not in (None, "") else None
            except ValueError:
                raise NmapXmlError(f"port {portid} has a non-numeric service conf") from None
            ports.append(PortResult(
                protocol=port.get("protocol", ""),
                port=portid,
                state=state.get("state"),
                reason=state.get("reason", ""),
                service=service.get("name", "") if service is not None else "",
                service_method=service.get("method", "") if service is not None else "",
                service_confidence=conf,
            ))
        if addr is None or not addr.get("addr"):
            raise NmapXmlError("host without an IPv4 address")
        hosts.append(HostResult(
            address=addr.get("addr"),
            status=status.get("state", "unknown") if status is not None else "unknown",
            ports=tuple(ports),
        ))
    return NmapReport(
        nmap_version=root.get("version", ""),
        args=root.get("args", ""),
        hosts=tuple(hosts),
        exit_status=finished.get("exit", ""),
    )
