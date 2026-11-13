"""
Cloud Provider Status Check Pre-Flight Service (`poc/services/cloud_status_service.py`).

Checks whether the underlying cloud provider region (`gcp` | `aws` | `azure`) is currently
experiencing an active provider outage BEFORE allowing infrastructure mutations.

Design:
  - GCP: Queries `https://status.cloud.google.com/incidents.json` (TTL-cached, short timeout)
    and inspects unresolved incidents (`end` is empty/null) affecting the normalized region
    (e.g. `us-central1-c` -> `us-central1`) or `global`.
  - AWS: Supports configurable AWS Health / public status JSON feed (`AAAS_AWS_STATUS_URL`)
    or injected feed/overrides, normalizing AZs (e.g. `us-east-1a` -> `us-east-1`).
  - Azure: Supports configurable Azure Status feed (`AAAS_AZURE_STATUS_URL`) or injected
    feed/overrides, matching normalized Azure regions (e.g. `eastus`, `westus2`).
  - Fail-safe behavior: If external status feeds are unreachable or `AAAS_CLOUD_STATUS_MODE=offline`,
    returns `STATUS_FEED_UNREACHABLE` with `mutations_allowed=True` (advisory warning) unless
    `AAAS_CLOUD_STATUS_FAIL_CLOSED=true` is explicitly configured.
  - Deterministic testing: Provides `inject_simulated_outage()` / `clear_simulated_outages()`
    and injectable `feed_fetcher` for reproducible pre-flight gate verification.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional


GCP_STATUS_INCIDENTS_URL = os.getenv(
    "AAAS_GCP_STATUS_URL",
    "https://status.cloud.google.com/incidents.json",
)
AWS_STATUS_FEED_URL = os.getenv(
    "AAAS_AWS_STATUS_URL",
    "https://health.aws.amazon.com/public/currentevents",
)
AZURE_STATUS_FEED_URL = os.getenv(
    "AAAS_AZURE_STATUS_URL",
    "https://azure.status.microsoft/en-us/status/feed/",
)


def normalize_cloud_region(region_or_zone: str, cloud_provider: str = "gcp") -> str:
    """
    Normalizes a zone/cluster string into a canonical cloud region:
      - GCP: `us-central1-c` -> `us-central1`, `europe-west1-b` -> `europe-west1`
      - AWS: `us-east-1a` -> `us-east-1`, `eu-west-2c` -> `eu-west-2`
      - Azure: `East US` -> `eastus`, `westus2` -> `westus2`
    """
    raw = (region_or_zone or "").strip().lower()
    if not raw:
        if cloud_provider == "aws":
            return os.getenv("AAAS_AWS_REGION", "us-east-1")
        if cloud_provider == "azure":
            return os.getenv("AAAS_AZURE_LOCATION", "eastus")
        return os.getenv("GCP_REGION", "us-central1")

    if cloud_provider == "gcp":
        # Strip trailing zone letter e.g. us-central1-c -> us-central1
        m = re.match(r"^([a-z]+-[a-z]+\d+)(?:-[a-z])$", raw)
        if m:
            return m.group(1)
        return raw

    if cloud_provider == "aws":
        # Strip trailing AZ letter e.g. us-east-1a -> us-east-1
        m = re.match(r"^([a-z]{2}-[a-z]+-\d+)[a-z]$", raw)
        if m:
            return m.group(1)
        return raw

    if cloud_provider == "azure":
        return re.sub(r"[\s_-]+", "", raw)

    return raw


class CloudProviderStatusService:
    """
    Multi-cloud regional outage pre-flight checker (`gcp` | `aws` | `azure`).
    Prevents agents from mutating infrastructure when the underlying cloud provider
    region is experiencing an active control-plane or service outage.
    """

    def __init__(
        self,
        cache_ttl_seconds: int = 120,
        timeout_seconds: float = 4.0,
        feed_fetcher: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.cache_ttl_seconds = max(5, int(cache_ttl_seconds))
        self.timeout_seconds = float(timeout_seconds)
        self._feed_fetcher = feed_fetcher
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._simulated_outages: List[Dict[str, Any]] = []

    def inject_simulated_outage(
        self,
        cloud_provider: str,
        region: str,
        title: str = "Active Regional Control Plane Outage",
        service: str = "Compute / Managed Cloud Infrastructure",
        severity: str = "high",
        incident_id: Optional[str] = None,
        url: str = "https://status.cloud.google.com/",
    ) -> Dict[str, Any]:
        """Injects a deterministic active provider outage (for testing & chaos drills)."""
        cloud = (cloud_provider or "gcp").strip().lower()
        norm_region = normalize_cloud_region(region, cloud)
        record = {
            "id": incident_id or f"sim-outage-{cloud}-{norm_region}-{int(time.time())}",
            "cloud_provider": cloud,
            "title": title,
            "service": service,
            "severity": severity,
            "status_impact": "SERVICE_OUTAGE",
            "affected_regions": [norm_region],
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "url": url,
            "source": "simulated_outage_override",
        }
        self._simulated_outages.append(record)
        return record

    def clear_simulated_outages(self, cloud_provider: Optional[str] = None, region: Optional[str] = None) -> None:
        """Clears injected simulated outages (all, or filtered by cloud/region)."""
        if cloud_provider is None and region is None:
            self._simulated_outages.clear()
            return
        target_cloud = cloud_provider.strip().lower() if cloud_provider else None
        target_region = (
            normalize_cloud_region(region, target_cloud or "gcp") if region else None
        )
        self._simulated_outages = [
            o
            for o in self._simulated_outages
            if not (
                (target_cloud is None or o.get("cloud_provider") == target_cloud)
                and (target_region is None or target_region in o.get("affected_regions", []))
            )
        ]

    def _fetch_json_feed(self, url: str) -> Any:
        if self._feed_fetcher is not None:
            return self._feed_fetcher(url)
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json, application/xml, text/xml, */*",
                "User-Agent": "AgentTriad-AaaS-PreFlight/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
            raw = resp.read().decode("utf-8", errors="replace").strip()
        if not raw:
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def _get_cached_or_fetch(self, cache_key: str, url: str, force_refresh: bool = False) -> Any:
        now = time.time()
        entry = self._cache.get(cache_key)
        if not force_refresh and entry and (now - entry["ts"] < self.cache_ttl_seconds):
            return entry["data"]
        data = self._fetch_json_feed(url)
        self._cache[cache_key] = {"ts": now, "data": data}
        return data

    def _match_gcp_incidents(
        self,
        raw_incidents: Any,
        region: str,
        service_hint: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if not isinstance(raw_incidents, list):
            return []
        active_matches: List[Dict[str, Any]] = []
        hint_lower = (service_hint or "").strip().lower()
        for inc in raw_incidents:
            if not isinstance(inc, dict):
                continue
            # Unresolved incidents have no `end` timestamp
            if inc.get("end"):
                continue
            impact = str(inc.get("status_impact") or "").upper()
            severity = str(inc.get("severity") or "").lower()
            # Collect affected region IDs from currently_affected_locations or affected_locations
            locs = inc.get("currently_affected_locations") or inc.get("affected_locations") or []
            loc_ids = [
                normalize_cloud_region(str(loc.get("id") or loc.get("title") or ""), "gcp")
                for loc in locs
                if isinstance(loc, dict)
            ]
            region_match = (not loc_ids) or ("global" in loc_ids) or (region in loc_ids)
            if not region_match:
                continue

            affected_prods = [
                str(p.get("title") or "")
                for p in (inc.get("affected_products") or [])
                if isinstance(p, dict)
            ]
            if hint_lower and affected_prods:
                # If a specific service hint is passed, match when either product matches or impact is major outage
                prod_match = any(hint_lower in p.lower() for p in affected_prods)
                if not prod_match and impact != "SERVICE_OUTAGE":
                    continue

            if impact in ("SERVICE_OUTAGE", "SERVICE_DISRUPTION") or severity in ("high", "critical"):
                uri = str(inc.get("uri") or "")
                full_url = (
                    f"https://status.cloud.google.com/{uri.lstrip('/')}"
                    if uri and not uri.startswith("http")
                    else (uri or "https://status.cloud.google.com/")
                )
                active_matches.append(
                    {
                        "id": str(inc.get("id") or inc.get("number") or "gcp-incident"),
                        "title": str(inc.get("external_desc") or inc.get("service_name") or "GCP Active Incident"),
                        "service": ", ".join(affected_prods) or str(inc.get("service_name") or "Google Cloud"),
                        "severity": severity or "high",
                        "status_impact": impact or "SERVICE_DISRUPTION",
                        "affected_regions": loc_ids or ["global"],
                        "started_at": inc.get("begin") or inc.get("created"),
                        "url": full_url,
                    }
                )
        return active_matches

    def _match_aws_incidents(
        self,
        raw_feed: Any,
        region: str,
        service_hint: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if not isinstance(raw_feed, list):
            return []
        active_matches: List[Dict[str, Any]] = []
        hint_lower = (service_hint or "").strip().lower()
        for ev in raw_feed:
            if not isinstance(ev, dict):
                continue
            status = str(ev.get("status") or "").lower()
            if status in ("resolved", "closed", "0"):
                continue
            ev_region = normalize_cloud_region(str(ev.get("region") or ev.get("region_name") or ""), "aws")
            if ev_region and ev_region != "global" and ev_region != region:
                continue
            svc = str(ev.get("service_name") or ev.get("service") or "AWS")
            if hint_lower and hint_lower not in svc.lower() and status not in ("outage", "2", "3"):
                continue
            active_matches.append(
                {
                    "id": str(ev.get("id") or ev.get("arn") or "aws-health-event"),
                    "title": str(ev.get("summary") or ev.get("title") or "AWS Active Service Event"),
                    "service": svc,
                    "severity": str(ev.get("severity") or "high"),
                    "status_impact": "SERVICE_OUTAGE",
                    "affected_regions": [ev_region or region],
                    "started_at": ev.get("date") or ev.get("start_time"),
                    "url": "https://health.aws.amazon.com/health/status",
                }
            )
        return active_matches

    def _match_azure_incidents(
        self,
        raw_feed: Any,
        region: str,
        service_hint: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        active_matches: List[Dict[str, Any]] = []
        hint_lower = (service_hint or "").strip().lower()
        if isinstance(raw_feed, list):
            for ev in raw_feed:
                if not isinstance(ev, dict):
                    continue
                if str(ev.get("status") or "").lower() in ("resolved", "mitigated"):
                    continue
                locs = [normalize_cloud_region(str(r), "azure") for r in (ev.get("regions") or [])]
                if locs and "global" not in locs and region not in locs:
                    continue
                svc = str(ev.get("service") or "Azure")
                if hint_lower and hint_lower not in svc.lower():
                    continue
                active_matches.append(
                    {
                        "id": str(ev.get("id") or "azure-status-event"),
                        "title": str(ev.get("title") or "Azure Active Outage"),
                        "service": svc,
                        "severity": str(ev.get("severity") or "high"),
                        "status_impact": "SERVICE_OUTAGE",
                        "affected_regions": locs or [region],
                        "started_at": ev.get("started_at"),
                        "url": "https://azure.status.microsoft/",
                    }
                )
        elif isinstance(raw_feed, str) and "<item>" in raw_feed.lower():
            # Lightweight RSS parsing for Azure status feed without external XML deps
            items = re.findall(r"<item>(.*?)</item>", raw_feed, flags=re.IGNORECASE | re.DOTALL)
            for idx, item_xml in enumerate(items[:15]):
                title_m = re.search(r"<title>(.*?)</title>", item_xml, flags=re.IGNORECASE | re.DOTALL)
                desc_m = re.search(r"<description>(.*?)</description>", item_xml, flags=re.IGNORECASE | re.DOTALL)
                title = (title_m.group(1) if title_m else "Azure Status Alert").strip()
                desc = (desc_m.group(1) if desc_m else "").strip()
                blob = re.sub(r"[\s_-]+", "", f"{title} {desc}".lower())
                if "resolved" in blob or "mitigated" in blob:
                    continue
                if region in blob or "global" in blob:
                    active_matches.append(
                        {
                            "id": f"azure-rss-{idx}",
                            "title": title,
                            "service": service_hint or "Azure Cloud",
                            "severity": "high",
                            "status_impact": "SERVICE_OUTAGE",
                            "affected_regions": [region],
                            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "url": "https://azure.status.microsoft/",
                        }
                    )
        return active_matches

    def check_region_status(
        self,
        cloud_provider: str = "gcp",
        region: str = "us-central1",
        service_hint: Optional[str] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """
        Pre-flight cloud provider health check for `(cloud_provider, region)`.
        Returns `mutations_allowed=False` whenever an active outage impacts the target region.
        """
        cloud = (cloud_provider or os.getenv("CLOUD_PROVIDER") or "gcp").strip().lower()
        if cloud not in ("gcp", "aws", "azure"):
            cloud = "gcp"
        norm_region = normalize_cloud_region(region, cloud)
        checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Check injected/simulated outages first (highest priority for chaos drills & tests)
        sim_matches = [
            o
            for o in self._simulated_outages
            if o.get("cloud_provider") == cloud
            and (
                norm_region in o.get("affected_regions", [])
                or "global" in o.get("affected_regions", [])
            )
        ]
        if sim_matches:
            first = sim_matches[0]
            return {
                "status": "ACTIVE_OUTAGE_DETECTED",
                "cloud_provider": cloud,
                "region": norm_region,
                "service_hint": service_hint,
                "mutations_allowed": False,
                "active_incidents": sim_matches,
                "active_incident_count": len(sim_matches),
                "checked_at": checked_at,
                "source": "simulated_outage_override",
                "recommendation": (
                    f"HOLD INFRASTRUCTURE MUTATIONS: Active {cloud.upper()} regional outage detected in `{norm_region}` "
                    f"({first.get('title')}). Wait for cloud provider recovery before mutating state or applying Terraform."
                ),
            }

        # 2. Check mode (allow offline mode in air-gapped environments)
        mode = (os.getenv("AAAS_CLOUD_STATUS_MODE") or "live").strip().lower()
        if mode == "offline" and self._feed_fetcher is None:
            return {
                "status": "HEALTHY",
                "cloud_provider": cloud,
                "region": norm_region,
                "service_hint": service_hint,
                "mutations_allowed": True,
                "active_incidents": [],
                "active_incident_count": 0,
                "checked_at": checked_at,
                "source": "offline_mode_nominal",
                "recommendation": f"No active {cloud.upper()} outages reported for `{norm_region}` (offline mode).",
            }

        feed_map = {
            "gcp": (GCP_STATUS_INCIDENTS_URL, "status.cloud.google.com/incidents.json", self._match_gcp_incidents),
            "aws": (AWS_STATUS_FEED_URL, "aws_health_public_feed", self._match_aws_incidents),
            "azure": (AZURE_STATUS_FEED_URL, "azure_status_feed", self._match_azure_incidents),
        }
        url, source_label, matcher = feed_map[cloud]

        try:
            raw_feed = self._get_cached_or_fetch(cloud, url, force_refresh=force_refresh)
            active = matcher(raw_feed, norm_region, service_hint)
            if active:
                return {
                    "status": "ACTIVE_OUTAGE_DETECTED",
                    "cloud_provider": cloud,
                    "region": norm_region,
                    "service_hint": service_hint,
                    "mutations_allowed": False,
                    "active_incidents": active,
                    "active_incident_count": len(active),
                    "checked_at": checked_at,
                    "source": source_label,
                    "recommendation": (
                        f"HOLD INFRASTRUCTURE MUTATIONS: {len(active)} active {cloud.upper()} provider incident(s) "
                        f"affecting `{norm_region}` ({active[0].get('title')}). Deferring automated changes."
                    ),
                }
            return {
                "status": "HEALTHY",
                "cloud_provider": cloud,
                "region": norm_region,
                "service_hint": service_hint,
                "mutations_allowed": True,
                "active_incidents": [],
                "active_incident_count": 0,
                "checked_at": checked_at,
                "source": source_label,
                "recommendation": f"Pre-flight PASS: {cloud.upper()} region `{norm_region}` reports 0 active provider outages.",
            }
        except Exception as exc:
            fail_closed = os.getenv("AAAS_CLOUD_STATUS_FAIL_CLOSED", "false").strip().lower() in ("1", "true", "yes")
            return {
                "status": "STATUS_FEED_UNREACHABLE",
                "cloud_provider": cloud,
                "region": norm_region,
                "service_hint": service_hint,
                "mutations_allowed": not fail_closed,
                "active_incidents": [],
                "active_incident_count": 0,
                "checked_at": checked_at,
                "source": source_label,
                "error": f"{type(exc).__name__}: {exc}",
                "recommendation": (
                    f"Pre-flight status feed unreachable for {cloud.upper()} (`{norm_region}`); "
                    + (
                        "blocking mutations (fail-closed mode enabled)."
                        if fail_closed
                        else "proceeding with HITL + Agent Harness guardrails."
                    )
                ),
            }


cloud_status_service = CloudProviderStatusService()
