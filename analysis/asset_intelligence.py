"""Deterministic asset identity and evidence-backed attack-surface relationships."""
import hashlib
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit

from core.scope import TargetScopeError, normalize_http_url, normalize_target


def _get(obj, key, default=None):
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


def _text(value, limit=2000):
    return value.strip()[:limit] if isinstance(value, str) else ""


def _hash(value):
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:24]


def _finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return float(value) if math.isfinite(value) else None
    except (OverflowError, ValueError):
        return None


def _safe_json(value, depth=0):
    if depth > 5:
        return None
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {str(key)[:100]: _safe_json(item, depth + 1)
                for key, item in list(value.items())[:50]
                if isinstance(key, (str, int, float, bool))}
    if isinstance(value, (list, tuple)):
        return [_safe_json(item, depth + 1) for item in value[:50]]
    return None


def _host(raw):
    raw = _text(raw)
    if not raw:
        return ""
    try:
        candidate = urlsplit(raw if "://" in raw else "http:" + raw).hostname if "://" in raw or raw.startswith("//") else raw
        return normalize_target(candidate or "")
    except (ValueError, TargetScopeError):
        return ""


def _kind(host):
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def _endpoint(raw):
    if not isinstance(raw, str) or len(raw.strip()) > 2048:
        return None
    try:
        parsed = normalize_http_url(raw.strip())
    except (TargetScopeError, TypeError, ValueError):
        return None
    path = parsed["path"] or "/"
    return {
        "url": parsed["url"] + path,
        "host": parsed["host"],
        "scheme": parsed["scheme"],
        "port": parsed["port"],
        "path": path,
    }


def _evidence(source, stamp, evidence):
    source, stamp, evidence = _text(source, 100) or "unknown", _text(stamp, 100), _text(evidence)
    return {
        "source_tool": source,
        "observed_at": stamp,
        "evidence_ref": _hash(source + "\0" + stamp + "\0" + evidence) if evidence else "",
        "evidence_excerpt": evidence[:500],
    }


class AssetIntelligenceBuilder:
    """Read-only session-to-graph projection with stable asset IDs."""

    def build(self, session):
        self.assets, self.edges, self.findings = {}, {}, {}
        self.root_host = _host(_get(session, "target", ""))
        self.root_id = self._host(self.root_host, "phantomx", _get(session, "started_at", ""),
                                  "Explicit assessment target.", "assessment_target") if self.root_host else ""
        results = list(_get(session, "results", []) or [])
        results.sort(key=lambda r: (_text(_get(r, "tool", "")).casefold(),
                                    _text(_get(r, "target", "")).casefold(),
                                    _text(_get(r, "started_at", ""))))
        for result in results:
            tool = _text(_get(result, "tool", "")) or "unknown"
            stamp = (_text(_get(result, "finished_at", "")) or
                     _text(_get(result, "started_at", "")) or
                     _text(_get(session, "started_at", "")))
            target = _text(_get(result, "target", ""))
            target_url = _endpoint(target)
            if target_url:
                _, host_id = self._endpoint(target_url["url"], tool, stamp, "Tool assessment target.")
            else:
                host = _host(target) or self.root_host
                host_id = self._host(host, tool, stamp, "Tool assessment target.", "assessment_target") if host else self.root_id
            for service in list(_get(result, "services", []) or []):
                host = _host(target) or self.root_host
                if not host:
                    continue
                parent = self._host(host, tool, stamp, _text(_get(service, "service", "")), "service_host")
                service_id = self._service(host, service, tool, stamp)
                self._edge(parent, "exposes", service_id, tool, stamp,
                           f"{_get(service, 'port', '')}/{_get(service, 'protocol', '')}")
            for endpoint in list(_get(result, "endpoints", []) or []):
                metadata = _get(endpoint, "metadata", {})
                endpoint_id, _ = self._endpoint(_get(endpoint, "url", ""),
                    _text(_get(endpoint, "source_tool", "")) or tool, stamp, "")
                if endpoint_id and isinstance(metadata, dict):
                    self._technologies(endpoint_id, metadata,
                        _text(_get(endpoint, "source_tool", "")) or tool, stamp)
            for observation in list(_get(result, "observations", []) or []):
                source = _text(_get(observation, "source_tool", "")) or tool
                evidence = _text(_get(observation, "evidence", ""))
                endpoint = _get(observation, "endpoint")
                if endpoint:
                    asset_id, _ = self._endpoint(_get(endpoint, "url", ""), source, stamp, evidence)
                else:
                    host = _host(_get(observation, "target", "")) or self.root_host
                    asset_id = self._host(host, source, stamp, evidence, "observation_target") if host else ""
                metadata = _get(observation, "metadata", {})
                if asset_id and isinstance(metadata, dict):
                    self._technologies(asset_id, metadata, source, stamp)
            for finding in list(_get(result, "findings", []) or []):
                self._finding(finding, host_id or self.root_id, tool, stamp)
            if tool.casefold() == "dnsx":
                self._dns(result, tool, stamp)
        assets = sorted(self.assets.values(), key=lambda x: (x["type"], x["asset_id"]))
        relationships = sorted(self.edges.values(), key=lambda x: (x["relationship"], x["source_id"], x["target_id"]))
        findings = sorted(self.findings.values(), key=lambda x: x["finding_ref"])
        coverage = self._coverage(results)
        summary = self._summary(assets, relationships, findings, coverage)
        return {
            "schema_version": 1, "root_asset_id": self.root_id,
            "assets": assets, "relationships": relationships,
            "findings": findings, "coverage": coverage, "summary": summary,
        }

    def _asset(self, kind, key, label, attrs, source, stamp, evidence):
        key = _text(key).casefold()
        if not key:
            return ""
        asset_id = kind + ":" + _hash(kind + "\0" + key)
        item = self.assets.setdefault(asset_id, {
            "asset_id": asset_id, "type": kind, "canonical_key": key,
            "display_name": _text(label) or key, "attributes": {},
            "attribute_variants": {}, "first_seen": _text(stamp, 100),
            "last_seen": _text(stamp, 100), "provenance": [],
        })
        for name, value in (attrs or {}).items():
            if not isinstance(name, str) or not name or value is None:
                continue
            if isinstance(value, (str, int, float, bool)):
                if isinstance(value, float) and not math.isfinite(value):
                    continue
                value = _text(value) if isinstance(value, str) else value
            elif isinstance(value, (list, tuple)):
                value = sorted({_text(x, 500) for x in value if isinstance(x, str) and _text(x, 500)})
            else:
                continue
            if name not in item["attributes"]:
                item["attributes"][name] = value
            elif item["attributes"][name] != value:
                variants = item["attribute_variants"].setdefault(name, [item["attributes"][name]])
                if value not in variants:
                    variants.append(value)
                    variants.sort(key=lambda x: json.dumps(x, sort_keys=True))
        stamp = _text(stamp, 100)
        if stamp and (not item["first_seen"] or stamp < item["first_seen"]):
            item["first_seen"] = stamp
        if stamp and stamp > item["last_seen"]:
            item["last_seen"] = stamp
        provenance = _evidence(source, stamp, evidence)
        encoded = json.dumps(provenance, sort_keys=True, ensure_ascii=True)
        if all(json.dumps(old, sort_keys=True, ensure_ascii=True) != encoded for old in item["provenance"]):
            item["provenance"].append(provenance)
            item["provenance"].sort(key=lambda x: (x["observed_at"], x["source_tool"], x["evidence_ref"]))
        return asset_id

    def _host(self, raw, source, stamp, evidence, role=""):
        host = _host(raw)
        if not host:
            return ""
        return self._asset(_kind(host), host, host, {"discovery_role": role} if role else {},
                           source, stamp, evidence)

    def _endpoint(self, raw, source, stamp, evidence):
        parsed = _endpoint(raw)
        if not parsed:
            return "", ""
        host_id = self._host(parsed["host"], source, stamp, evidence, "endpoint_host")
        endpoint_id = self._asset("endpoint", parsed["url"], parsed["url"], {
            "scheme": parsed["scheme"], "host": parsed["host"],
            "port": parsed["port"], "path": parsed["path"],
        }, source, stamp, evidence)
        self._edge(host_id, "serves", endpoint_id, source, stamp, evidence)
        return endpoint_id, host_id

    def _service(self, host, service, source, stamp):
        protocol = _text(_get(service, "protocol", "")).casefold()
        try:
            port = int(_get(service, "port"))
        except (TypeError, ValueError, OverflowError):
            return ""
        if protocol not in {"tcp", "udp", "sctp"} or not 1 <= port <= 65535:
            return ""
        name, version = _text(_get(service, "service", ""), 200), _text(_get(service, "version", ""), 500)
        display_host = f"[{host}]" if ":" in host else host
        return self._asset("service", f"{host}|{protocol}|{port}", f"{display_host}:{port}/{protocol}", {
            "host": host, "protocol": protocol, "port": port,
            "state": _text(_get(service, "state", ""), 50),
            "service_names": [name] if name else [],
            "versions": [version] if version else [],
        }, source, stamp, f"{name} {version}".strip())

    def _technologies(self, parent_id, metadata, source, stamp):
        values = []
        for key in ("technologies", "technology"):
            candidate = metadata.get(key)
            if isinstance(candidate, str):
                values.extend(candidate.split(","))
            elif isinstance(candidate, (list, tuple)):
                values.extend(x for x in candidate if isinstance(x, str))
        if isinstance(metadata.get("webserver"), str):
            values.append(metadata["webserver"])
        for value in values:
            name = _text(value, 200)
            if not name:
                continue
            tech_id = self._asset("technology", name.casefold(), name, {"name": name}, source, stamp, name)
            self._edge(parent_id, "uses_technology", tech_id, source, stamp, name)

    def _finding(self, finding, fallback_id, source, stamp):
        finding_id = _text(_get(finding, "finding_id", ""), 200)
        if not finding_id:
            return
        ref = "finding:" + finding_id
        metadata = _get(finding, "metadata", {})
        metadata = metadata if isinstance(metadata, dict) else {}
        tool = _text(_get(finding, "source_tool", "")) or source
        evidence = _text(_get(finding, "evidence", ""))
        title = _text(_get(finding, "title", ""))
        affected = []
        endpoint_id = host_id = ""
        for key in ("matched_at", "url", "endpoint", "endpoint_url", "affected_url"):
            raw_url = metadata.get(key)
            if isinstance(raw_url, str):
                endpoint_id, host_id = self._endpoint(raw_url, tool, stamp, evidence)
                if endpoint_id:
                    self._technologies(endpoint_id, metadata, tool, stamp)
                    break

        raw_host = metadata.get("hostname") or metadata.get("host") or metadata.get("ip")
        discovered = _host(raw_host) if isinstance(raw_host, str) else ""
        discovered_id = ""
        if discovered:
            is_subdomain = (
                tool.casefold() == "subfinder"
                and self.root_host
                and discovered.endswith("." + self.root_host)
            )
            discovered_id = self._host(
                discovered, tool, stamp, evidence,
                "subdomain" if is_subdomain else "discovered_host",
            )
            if self.root_id and discovered != self.root_host:
                relation = "discovers" if is_subdomain else "associated_with"
                self._edge(self.root_id, relation, discovered_id, tool, stamp, evidence)

        link_basis = ""
        path = metadata.get("path")
        target_url = _endpoint(_get(finding, "target", ""))
        if not endpoint_id and isinstance(path, str) and 0 < len(path) <= 1000 and not any(
            char in path for char in ("\0", "\n", "\r")
        ):
            if target_url:
                endpoint_id, host_id = self._endpoint(
                    target_url["url"].rstrip("/") + "/" + path.lstrip("/"),
                    tool, stamp, evidence,
                )
                if endpoint_id:
                    link_basis = "path_metadata"
            else:
                target_host = _host(_get(finding, "target", "")) or self.root_host
                parent_id = self._host(
                    target_host, tool, stamp, evidence, "resource_host",
                ) if target_host else ""
                if parent_id:
                    resource_id = self._asset(
                        "resource", parent_id + "|" + path,
                        target_host + "/" + path.lstrip("/"),
                        {"host": target_host, "path": path[:1000]},
                        tool, stamp, evidence,
                    )
                    self._edge(parent_id, "contains_resource", resource_id, tool, stamp, evidence)
                    affected.append(resource_id)
                    link_basis = "path_metadata"

        if endpoint_id:
            affected.extend([endpoint_id, host_id])
            link_basis = link_basis or "endpoint_metadata"
        elif discovered_id:
            affected.append(discovered_id)
            link_basis = "discovered_hostname"
        elif not affected:
            target = _text(_get(finding, "target", ""))
            target_url = _endpoint(target)
            if target_url:
                endpoint_id, host_id = self._endpoint(
                    target_url["url"], tool, stamp, evidence,
                )
                affected.extend([endpoint_id, host_id])
                link_basis = "finding_target"
            else:
                target_host = _host(target)
                target_id = self._host(
                    target_host, tool, stamp, evidence, "finding_target",
                ) if target_host else ""
                if target_id:
                    affected.append(target_id)
                    link_basis = "finding_target"

        affected = sorted(set(x for x in affected if x))
        context_id = "" if affected else fallback_id
        verification = _text(metadata.get("verification_status"), 100) or "not_provided"
        def number(field):
            return _finite_number(_get(finding, field))

        identifiers = [
            (key, metadata[key].strip().casefold())
            for key in ("cve", "cve_id", "vulnerability_id", "template_id")
            if isinstance(metadata.get(key), str) and metadata[key].strip()
        ]
        if not identifiers:
            cve = re.search(r"\bCVE-\d{4}-\d{4,}\b", title + " " + evidence, re.I)
            if cve:
                identifiers.append(("cve", cve.group(0).casefold()))
        fingerprint = ""
        if identifiers:
            identity = [
                sorted(identifiers),
                _text(_get(finding, "category", "")).casefold(),
                re.sub(r"\s+", " ", title).casefold(),
                affected,
            ]
            fingerprint = "fp:" + _hash(json.dumps(identity, sort_keys=True))

        score_breakdown = _safe_json(_get(finding, "score_breakdown", {}))
        if not isinstance(score_breakdown, dict):
            score_breakdown = {}
        verification_evidence = _text(metadata.get("verification_evidence"))
        self.findings[ref] = {
            "finding_ref": ref,
            "finding_id": finding_id,
            "stable_fingerprint": fingerprint,
            "title": title,
            "category": _text(_get(finding, "category", "")),
            "severity": _text(_get(finding, "severity", "info"), 50),
            "scanner_severity": _text(_get(finding, "scanner_severity", ""), 100),
            "risk_score": number("score"),
            "confidence": number("confidence"),
            "impact": number("impact"),
            "exploitability": number("exploitability"),
            "exposure": number("exposure"),
            "score_breakdown": score_breakdown,
            "verification_status": verification,
            "verification_method": _text(metadata.get("verification_method"), 200),
            "verification_reason": _text(metadata.get("verification_reason"), 1000),
            "verification_evidence_ref": _hash(verification_evidence) if verification_evidence else "",
            "verified_at": _text(metadata.get("verified_at"), 100),
            "recommendation": _text(_get(finding, "recommendation", ""), 2000),
            "source_tool": tool,
            "asset_link_basis": link_basis or ("assessment_context" if context_id else "unresolved"),
            "affected_asset_ids": affected,
            "context_asset_id": context_id,
            "evidence_ref": _hash(tool + "\0" + finding_id + "\0" + evidence) if evidence else "",
        }
        for asset_id in affected:
            self._edge(asset_id, "has_finding", ref, tool, stamp, evidence)
        if context_id:
            self._edge(context_id, "assessment_context_for", ref, tool, stamp, evidence)

    def _dns(self, result, source, stamp):
        output = _get(result, "stdout", "")
        if not isinstance(output, str):
            return
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                item = None
            if isinstance(item, dict):
                owner = item.get("host") or item.get("name") or item.get("input") or self.root_host
                for rrtype in ("A", "AAAA", "CNAME"):
                    values = item.get(rrtype.lower())
                    if isinstance(values, str):
                        values = [values]
                    if isinstance(values, list):
                        for value in values[:20]:
                            self._dns_record(owner, rrtype, value, source, stamp, line)
                continue
            match = re.match(r"^(?P<host>[A-Za-z0-9._-]+)\s+(?:\[(?P<rr>A|AAAA|CNAME)\]|(?P<plain>A|AAAA|CNAME))\s+(?P<value>\S+)", line, re.I)
            if match:
                self._dns_record(match.group("host"), (match.group("rr") or match.group("plain")).upper(),
                                 match.group("value"), source, stamp, line)

    def _dns_record(self, owner, rrtype, value, source, stamp, evidence):
        owner, value, rrtype = _host(owner), _text(value, 500).rstrip("."), _text(rrtype, 20).upper()
        if not owner or not value or rrtype not in {"A", "AAAA", "CNAME"}:
            return
        ip = ""
        alias = ""
        if rrtype in {"A", "AAAA"}:
            try:
                ip = ipaddress.ip_address(value).compressed
            except ValueError:
                return
            if (rrtype == "A") != (ipaddress.ip_address(ip).version == 4):
                return
        elif rrtype == "CNAME":
            alias = _host(value)
            if not alias:
                return
        owner_id = self._host(owner, source, stamp, evidence, "dns_owner")
        record_id = self._asset("dns_record", owner + "|" + rrtype + "|" + value.casefold(),
            f"{owner} {rrtype} {value}", {"owner": owner, "record_type": rrtype, "value": value},
            source, stamp, evidence)
        self._edge(owner_id, "has_dns_record", record_id, source, stamp, evidence)
        if ip:
            ip_id = self._host(ip, source, stamp, evidence, "resolved_address")
            self._edge(owner_id, "resolves_to", ip_id, source, stamp, evidence)
            self._edge(record_id, "resolves_to", ip_id, source, stamp, evidence)
        elif alias:
            alias_id = self._host(alias, source, stamp, evidence, "cname_target")
            self._edge(owner_id, "aliases_to", alias_id, source, stamp, evidence)

    def _edge(self, source_id, relation, target_id, source, stamp, evidence):
        if not source_id or not target_id or source_id == target_id:
            return
        key = json.dumps([source_id, relation, target_id], ensure_ascii=True)
        edge_id = "rel:" + _hash(key)
        edge = self.edges.setdefault(edge_id, {
            "relationship_id": edge_id, "source_id": source_id,
            "relationship": relation, "target_id": target_id, "provenance": [],
        })
        proof = _evidence(source, stamp, evidence)
        encoded = json.dumps(proof, sort_keys=True, ensure_ascii=True)
        if all(json.dumps(old, sort_keys=True, ensure_ascii=True) != encoded for old in edge["provenance"]):
            edge["provenance"].append(proof)
            edge["provenance"].sort(key=lambda x: (x["observed_at"], x["source_tool"], x["evidence_ref"]))

    @staticmethod
    def _coverage(results):
        statuses, tools = {}, []
        for result in results:
            tool = _text(_get(result, "tool", "")) or "unknown"
            status = _text(_get(result, "status", "unknown")) or "unknown"
            statuses[status] = statuses.get(status, 0) + 1
            tools.append({
                "tool": tool, "target": _text(_get(result, "target", "")),
                "status": status, "return_code": _safe_json(_get(result, "return_code")),
                "finding_count": len(_get(result, "findings", []) or []),
            })
        tools.sort(key=lambda x: (x["tool"].casefold(), x["target"], x["status"]))
        return {"result_count": len(results), "status_counts": dict(sorted(statuses.items())), "tools": tools}

    @staticmethod
    def _summary(assets, edges, findings, coverage):
        by_type, by_relation, by_verification = {}, {}, {}
        for item in assets:
            by_type[item["type"]] = by_type.get(item["type"], 0) + 1
        for item in edges:
            key = item["relationship"]
            by_relation[key] = by_relation.get(key, 0) + 1
        linked = 0
        for item in findings:
            key = item["verification_status"]
            by_verification[key] = by_verification.get(key, 0) + 1
            linked += bool(item["affected_asset_ids"])
        return {
            "asset_count": len(assets), "assets_by_type": dict(sorted(by_type.items())),
            "relationship_count": len(edges), "relationships_by_type": dict(sorted(by_relation.items())),
            "finding_count": len(findings), "findings_with_assets": linked,
            "findings_without_assets": len(findings) - linked,
            "findings_by_verification_status": dict(sorted(by_verification.items())),
            "tool_result_count": coverage["result_count"],
            "tool_status_counts": coverage["status_counts"],
        }
