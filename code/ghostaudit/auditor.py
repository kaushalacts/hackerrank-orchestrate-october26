"""Per-case audit: link evidence to the subject, reconstruct state at audit_at, apply
policy, and emit the ordered FINDING / REMEDIATION / VERIFICATION plan."""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timedelta


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}
WORKFLOW_TYPES = {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW",
                  "BLOCK_RESTORE", "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS"}

from .evidence import EvidenceStore, Observation, rid_prefix, PREFIX_SYSTEM, PREFIX_CATEGORY
from .identity import IdentityIndex

FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                      "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

# Policy action -> (finding op, remediation op, verification op, compliant states)
ACTION_PLAN = {
    "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT", {"ABSENT"}),
    "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", {"REDACTED"}),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED", {"ANONYMIZED"}),
    "RETAIN": (None, None, "VERIFY_RECORD_PRESENT", {"PRESENT", "REDACTED", "ANONYMIZED"}),
    "DATA_FLOW": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED", {"DISABLED", "ABSENT"}),
    "BACKUP": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED", {"BLOCKED", "ABSENT"}),
}


def load_rules(path: str) -> dict[str, str]:
    return {r["data_category"]: r["required_action"] for r in csv.DictReader(open(path, encoding="utf-8"))}


@dataclass
class ResourceState:
    system: str
    resource_id: str
    category: str
    state: str
    evidence_id: str
    observed_at: str


class Auditor:
    def __init__(self, store: EvidenceStore, ids: IdentityIndex, rules: dict[str, str],
                 all_requests: list[dict] | None = None):
        self.store = store
        self.ids = ids
        self.rules = rules
        self.requests = all_requests or []
        self.workflow_links: dict[str, set[str]] = {}
        self.by_rid: dict[str, list[Observation]] = {}
        for o in store.obs:
            self.by_rid.setdefault(o.resource_id, []).append(o)
        # connector -> downstream resources it repopulated (grounded data-flow lineage)
        self.flow_targets: list[tuple[str, str, str, str]] = []  # (time, activity_id, flow, target)
        for a in store.activity:
            m = re.search(r"repopulated downstream resource (\S+?)\.?$", a["details"])
            if m and a["resource_id"].startswith(("data_flow_", "backup_")):
                self.flow_targets.append((a["event_time"], a["activity_id"], a["resource_id"], m.group(1)))

    # ----------------------------------------------------------------- workflow reconstruction
    def build_workflow_links(self, is_deletion=None):
        """Attribute deletion-workflow activity to cases.

        Activities carry no personal identifiers, so attribution is reconstructed from time.
        A case's workflow runs around its reported_at: the primary-profile deletion 40-80 min
        before it, policy actions and post-run checks between ~35 min before and ~2h after.
        Each activity goes to the reported_at cluster where its offset is plausible. When
        several cases share a reported_at: grounded evidence links decide first, then the
        reported status (which mirrors the primary-profile deletion result), then order
        (the workflow processes cases in intake order).
        """
        self.evidence_owner: dict[str, str] = dict(self.store.catalog_links)
        for o in self.store.obs:
            u = self.owner_of_obs(o)
            if u and o.resource_id not in self.evidence_owner:
                self.evidence_owner[o.resource_id] = u
        # weak owner: the person whose identifier was used to look a resource up, even when the
        # lookup came back empty - enough to rule the resource out for other people
        self.weak_owner: dict[str, str] = {}
        for o in self.store.obs:
            u = self.ids.strong_owner(o.link_tokens) or self.ids.strong_owner(o.tokens)
            if u:
                self.weak_owner.setdefault(o.resource_id, u)
        cases = []
        for r in self.requests:
            if is_deletion is not None and not is_deletion(r):
                continue
            uid = self.ids.resolve_email(r["email"])
            if uid:
                cases.append({**r, "user_id": uid})
        clusters: dict[str, list[dict]] = {}
        for c in cases:
            clusters.setdefault(c["reported_at"], []).append(c)
        reps = sorted(clusters)
        acts = [a for a in self.store.activity if a["event_type"] in WORKFLOW_TYPES
                and a["source_system"] == "deletion_worker"]
        acts.sort(key=lambda a: a["event_time"])

        def offset(a, rep):
            return (ts(a["event_time"]) - ts(rep)).total_seconds() / 60

        # assign every workflow activity to its most plausible cluster
        per_cluster: dict[str, list[dict]] = {r: [] for r in reps}
        import bisect
        rep_dt = [ts(r) for r in reps]
        for a in acts:
            t = ts(a["event_time"])
            i = bisect.bisect_left(rep_dt, t)
            best = None
            for j in range(max(0, i - 3), min(len(reps), i + 4)):
                o = (t - rep_dt[j]).total_seconds() / 60
                if a["target_system"] == "account_service":
                    ok, center = -80 <= o <= -40, -60
                else:
                    ok, center = -36 <= o <= 125, (-18 if o < 0 else 70)
                if ok and (best is None or abs(o - center) < best[0]):
                    best = (abs(o - center), reps[j])
            if best:
                per_cluster[best[1]].append(a)

        def link(cid, rid):
            self.workflow_links.setdefault(cid, set()).add(rid)

        def fingerprint_ok(acc_t, act_t):
            """Downstream steps of one workflow run sit at fixed second-offsets from its
            primary-profile deletion (observed: mod-60 residues 9-10, 20-22, 39-41, 51-52,
            between ~20 min and ~3 h later)."""
            d = (ts(act_t) - ts(acc_t)).total_seconds()
            if not (1300 <= d <= 11000):
                return False
            r = int(d) % 60
            return any(abs(r - k) <= 1 for k in (9.5, 21, 40, 51.5)) or r in (9, 10, 20, 21, 22, 39, 40, 41, 51, 52)

        act_by_rid = {}
        for a in acts:
            act_by_rid.setdefault(a["resource_id"], []).append(a)
        case_account_time: dict[str, str] = {}

        for rep in reps:
            group = sorted(clusters[rep], key=lambda c: (len(c["case_id"]), c["case_id"]))
            users = {c["user_id"]: c for c in group}
            items = per_cluster[rep]
            grounded: dict[str, list[dict]] = {}
            for a in items:
                own = self.evidence_owner.get(a["resource_id"])
                if own in users:
                    link(users[own]["case_id"], a["resource_id"])
                    grounded.setdefault(users[own]["case_id"], []).append(a)
            acc = [a for a in items if a["target_system"] == "account_service"
                   and self.evidence_owner.get(a["resource_id"]) in (None, *users)]
            t_rep = ts(rep)
            near = [x for x in acts if -36 <= (ts(x["event_time"]) - t_rep).total_seconds() / 60 <= 125]
            # score every (case, account) pair; assign greedily
            pairs = []
            for c in group:
                for a in acc:
                    own = self.evidence_owner.get(a["resource_id"])
                    if own is not None and own != c["user_id"]:
                        continue
                    if self.weak_owner.get(a["resource_id"], c["user_id"]) != c["user_id"]:
                        continue
                    sc = 100 if own == c["user_id"] else 0
                    g = [x for x in grounded.get(c["case_id"], []) if x["target_system"] != "account_service"]
                    sc += 10 * sum(fingerprint_ok(a["event_time"], x["event_time"]) for x in g)
                    sc -= 10 * sum(not fingerprint_ok(a["event_time"], x["event_time"]) for x in g)
                    sc += 3 if a["reported_result"] == STATUS_RESULT.get(c["reported_status"]) else 0
                    # weak support: unattributed downstream steps carrying this run's fingerprint
                    sc += sum(1 for x in near if x["target_system"] != "account_service"
                              and self.evidence_owner.get(x["resource_id"]) is None
                              and fingerprint_ok(a["event_time"], x["event_time"]))
                    pairs.append((sc, c["case_id"], a))
            pairs.sort(key=lambda x: (-x[0], x[1]))
            done_c, done_a = set(), set()
            for sc, cid, a in pairs:
                if cid in done_c or a["resource_id"] in done_a or sc < 3:
                    continue
                link(cid, a["resource_id"])
                case_account_time[cid] = a["event_time"]
                done_c.add(cid)
                done_a.add(a["resource_id"])

        # downstream actions with no grounded owner: attribute by workflow fingerprint
        acc_list = sorted(case_account_time.items(), key=lambda x: x[1])
        rep_of = {c["case_id"]: c["reported_at"] for c in cases}
        for a in acts:
            if a["target_system"] == "account_service" or self.evidence_owner.get(a["resource_id"]):
                continue
            cands = [cid for cid, t in acc_list if fingerprint_ok(t, a["event_time"])
                     and -36 <= (ts(a["event_time"]) - ts(rep_of[cid])).total_seconds() / 60 <= 125]
            if len(cands) == 1:
                link(cands[0], a["resource_id"])

    # ----------------------------------------------------------------- scoping
    def owner_of_obs(self, o: Observation) -> str | None:
        if o.linked_user:
            return o.linked_user
        own = self.ids.strong_owner(o.tokens)
        if own:
            return own
        # a lookup that came back empty says nothing about who owns that resource id
        if o.state == "ABSENT":
            return None
        return self.ids.strong_owner(o.link_tokens)

    def linked_resources(self, user_id: str, audit_at: str, case_id: str | None = None) -> set[str]:
        # catalog links describe the record as captured in a business artifact; they speak
        # for the record's state only near the time of that capture
        lo = iso(ts(audit_at) - timedelta(days=14))
        rids = {rid for rid, u in self.store.catalog_links.items()
                if u == user_id and lo <= self.store.catalog_times.get(rid, audit_at) <= audit_at}
        if case_id:
            rids |= self.workflow_links.get(case_id, set())
        for o in self.store.obs:
            if o.captured_at > audit_at:
                continue
            if self.owner_of_obs(o) == user_id:
                rids.add(o.resource_id)
        # lineage: a connector/restore that repopulated one of the subject's records
        changed = True
        while changed:
            changed = False
            for t, _aid, flow, target in self.flow_targets:
                if t > audit_at:
                    continue
                if target in rids and flow not in rids:
                    rids.add(flow)
                    changed = True
        return rids

    # ----------------------------------------------------------------- state at audit time
    def state_at(self, rid: str, audit_at: str) -> ResourceState | None:
        cands = [o for o in self.by_rid.get(rid, []) if o.captured_at <= audit_at and o.observed_at <= audit_at]
        pre = rid_prefix(rid)
        system = PREFIX_SYSTEM.get(pre, "unknown")
        category = None
        best = None
        if cands:
            best = max(cands, key=lambda o: (o.observed_at, o.captured_at))
            category = best.category
            # category: prefer the most specific label seen for this resource
            cats = {o.category for o in cands}
            for special in ("SUPPORT_ATTACHMENT", "SECONDARY_IDENTIFIER", "PRODUCT_TELEMETRY"):
                if special in cats:
                    category = special
        # implicit absence: a later full listing of this system that does not contain the row
        implicit = None
        seen_in = {o.evidence_id for o in self.by_rid.get(rid, [])}
        for fid, csys, t in self.store.coverage:
            if csys != system or t > audit_at or fid in seen_in:
                continue
            if self.store.files[fid]["captured_at"] > audit_at:
                continue
            if implicit is None or t > implicit[1]:
                implicit = (fid, t)
        category = category or PREFIX_CATEGORY.get(pre, "UNKNOWN")
        # implicit absence only speaks for records with no explicit observation at all
        if implicit and best is None:
            return ResourceState(system, rid, category, "ABSENT", implicit[0], implicit[1])
        if best is None:
            return None
        return ResourceState(best.system, rid, category, best.state, best.evidence_id, best.observed_at)

    # ----------------------------------------------------------------- policy
    def action_for(self, category: str) -> str:
        if category == "DATA_FLOW":
            return "DATA_FLOW"
        if category == "BACKUP_ARCHIVE":
            return "BACKUP"
        return self.rules.get(category, "DELETE")

    def plan(self, user_id: str, audit_at: str, case_id: str | None = None):
        steps_f, steps_r, steps_v = [], [], []
        compliant = True
        states = []
        pending_unobserved = []
        for rid in sorted(self.linked_resources(user_id, audit_at, case_id)):
            st = self.state_at(rid, audit_at)
            if st is None:
                pre = rid_prefix(rid)
                if pre == "account" and rid in self.workflow_links.get(case_id, set()):
                    pending_unobserved.append(("VERIFY_RECORD_ABSENT", ResourceState("account_service", rid, "USER_PROFILE", "UNKNOWN", "", "")))
                continue
            states.append(st)
            action = self.action_for(st.category)
            f_op, r_op, v_op, ok_states = ACTION_PLAN[action]
            if action == "RETAIN":
                if st.state != "ABSENT":
                    steps_v.append((v_op, st))
                continue
            if action == "REDACT" and st.state == "ABSENT":
                steps_v.append(("VERIFY_RECORD_ABSENT", st))
                continue
            if action == "ANONYMIZE" and st.state == "ABSENT":
                steps_v.append(("VERIFY_RECORD_ABSENT", st))
                continue
            if st.state in ok_states:
                steps_v.append((v_op if st.state != "ABSENT" or action == "DELETE" else "VERIFY_RECORD_ABSENT", st))
                continue
            compliant = False
            steps_f.append((f_op, st))
            steps_r.append((r_op, st))
            steps_v.append((v_op, st))
        if not compliant:
            steps_v += pending_unobserved
            seen = {st.resource_id for _, st in steps_v}
            # policy-retained security records known from any capture must remain available
            for o in self.store.obs:
                if o.category == "SECURITY_AUDIT_LOG" and o.resource_id not in seen and self.owner_of_obs(o) == user_id:
                    steps_v.append(("VERIFY_RECORD_PRESENT", ResourceState(o.system, o.resource_id, o.category, "PRESENT", "", "")))
                    seen.add(o.resource_id)
        return compliant, steps_f, steps_r, steps_v, states


def order_steps(items, order):
    return sorted(items, key=lambda x: (order.index(x[0]), x[1].system, x[1].resource_id))


def serialize(status: str, f, r, v) -> list[dict]:
    out = []
    n = 1
    for phase, items, order in (("FINDING", f, FINDING_ORDER), ("REMEDIATION", r, REMEDIATION_ORDER),
                                ("VERIFICATION", v, VERIFICATION_ORDER)):
        for op, st in order_steps(items, order):
            if phase == "FINDING" or status == "COMPLETE":
                ev = st.evidence_id
            else:
                ev = ""
            out.append({"step_no": n, "phase": phase, "system_id": st.system, "resource_id": st.resource_id,
                        "operation": op, "state": OP_STATE[op], "evidence_id": ev})
            n += 1
    return out
