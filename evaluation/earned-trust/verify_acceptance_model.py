#!/usr/bin/env python3
"""Independent executable adversarial-control oracle for the finite ETP
acceptance model (Phase 16.1b).

This program is an independent executable model of the finite acceptance
predicate that `tests/proof/coq/etp_acceptance.v` mechanises (Phase 16.1a).
It re-implements the predicate from its stated semantics:

    policy_satisfied p s
    and s.reported_claim = c
    and every premise of the chosen finite derivation is
        present, unchallenged and unrevoked

Independence in the narrow, checkable sense used here:

- it does not import, link, shell out to or read the Rust crate;
- it does not read, parse or re-use the Coq development at runtime;
- it uses only the Python standard library.

Independence here does not mean independent authorship. The same agent wrote
this oracle and the Phase 16.1a model file, so agreement between them is
instrument parity, not independent confirmation.

Authentication is deliberately absent from the acceptance rule: a valid
signature is not semantic support. The positive control keeps
`authenticated = true` to make that visible.

Exit status: 0 only if every control passes, 1 otherwise. The machine-readable
receipt goes to stdout and to `--out`; human PASS/FAIL lines go to stderr.

What this is: an executable conformance oracle over a finite abstract model.
What this is not: a Coq proof, Rust verification, memory-safety evidence, or
certification.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

SCHEMA_ID = "frf-etp-acceptance-controls.v1"

# ---------------------------------------------------------------------------
# 1. Finite universe
# ---------------------------------------------------------------------------

PREMISE_IDS = ("pA", "pB", "pC", "pD")
CLAIM_IDS = ("c0", "c1", "c2")

# The four constructors of the finite derivation grammar, in declaration order.
# A derivation is a finite nested tuple:
#   ("c0", "pA")   c0 from pA      (derive_c0_from_a)
#   ("c1", "pB")   c1 from pB      (derive_c1_from_b)
#   ("c0", "pC")   c0 from pC      (derive_c0_from_c)
#   ("c2", d0, d1) c2 from c0, c1  (derive_c2_from_c0_c1)
LEAF_RULES = (
    ("c0", "pA"),
    ("c1", "pB"),
    ("c0", "pC"),
)
BINARY_CHILD_CLAIMS = ("c0", "c1")

EVALUATED_CLAIM = "c2"
VALID_DERIVATION = ("c2", ("c0", "pA"), ("c1", "pB"))

CLAIM_CEILING = (
    "This receipt is the output of an independent executable conformance "
    "oracle for a finite abstract acceptance model. It is not a Coq proof, "
    "not verification of the Rust crate or any native execution, not "
    "memory-safety evidence, and not certification. It establishes only that, "
    "for the sixteen control instances recorded here, this executable model "
    "admits the fully valid instance and refuses each mutated instance, and "
    "that each primary refusal is reversed when only the mutated field is "
    "restored. It says nothing about whether the Coq model, the Rust "
    "implementation or any real campaign agrees with this model."
)

NON_CLAIMS = (
    "Not a proof: no theorem is stated or checked here; these are executed "
    "assertions about one finite model.",
    "Not Rust verification: no Rust source, binary or test was read, built or "
    "run.",
    "Not memory safety evidence: the subject is an abstract acceptance "
    "predicate, not program memory.",
    "Not refinement: no correspondence between this model and "
    "tests/proof/coq/etp_acceptance.v or the Rust crate is established.",
    "Not independent confirmation: the same agent authored the Phase 16.1a "
    "model and this oracle.",
    "Not certification, qualification or authorization to deploy.",
    "Not completeness: the controls are a declared finite set, not an "
    "exhaustive analysis of the policy space.",
)


# ---------------------------------------------------------------------------
# 2. Derivations: finite structures only
# ---------------------------------------------------------------------------


class DerivationError(Exception):
    """A support object that is not a finite well-typed derivation."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code + (":" + detail if detail else ""))

    @property
    def reason(self) -> str:
        return str(self)


def render(value: object, _stack: frozenset | None = None) -> str:
    """Deterministic, cycle-safe textual form of a support structure."""
    if _stack is None:
        _stack = frozenset()
    if isinstance(value, str):
        return value
    if isinstance(value, (tuple, list)):
        if id(value) in _stack:
            return "<cycle>"
        inner = _stack | {id(value)}
        opener, closer = ("(", ")") if isinstance(value, tuple) else ("[", "]")
        return opener + ", ".join(render(item, inner) for item in value) + closer
    if isinstance(value, dict):
        if id(value) in _stack:
            return "<cycle>"
        inner = _stack | {id(value)}
        return "{" + ", ".join(
            render(key, inner) + "=" + render(val, inner)
            for key, val in sorted(value.items(), key=lambda kv: str(kv[0]))
        ) + "}"
    return repr(value)


def _scan_cycles(value: object, stack: frozenset) -> None:
    """Refuse a support object that refers to itself.

    The object graph is finite; only its unfolding would be infinite. This is
    what makes the cyclic marker honest: no infinite object is constructed.
    """
    if not isinstance(value, (tuple, list, dict)):
        return
    if id(value) in stack:
        raise DerivationError(
            "cyclic_marker_not_finite", "self-referential support object"
        )
    inner = stack | {id(value)}
    items = value.values() if isinstance(value, dict) else value
    for item in items:
        _scan_cycles(item, inner)


def _typed_derivation(node: object) -> tuple[str, tuple[str, ...], int]:
    """Type a finite derivation node, returning (claim, leaves, size)."""
    if not isinstance(node, tuple):
        raise DerivationError(
            "not_a_finite_derivation", "support must be a finite tuple"
        )
    if len(node) == 0:
        raise DerivationError("empty_support", "empty support tuple has no leaves")
    tag = node[0]
    if tag == "cycle":
        raise DerivationError("cyclic_marker_not_finite", "explicit cycle marker")
    if not isinstance(tag, str) or tag not in CLAIM_IDS:
        raise DerivationError("not_a_claim_id", render(tag))

    if tag in ("c0", "c1"):
        if len(node) == 1:
            raise DerivationError("empty_support", tag + " leaf carries no premise")
        if len(node) != 2:
            raise DerivationError("arity_mismatch", tag + " leaf arity")
        premise = node[1]
        if premise not in PREMISE_IDS:
            raise DerivationError("unknown_premise", render(premise))
        if (tag, premise) not in LEAF_RULES:
            raise DerivationError("ungrammatical_leaf", tag + "<-" + premise)
        return tag, (premise,), 1

    # tag == "c2": the binary rule, indexed by the claims of its children.
    if len(node) == 1:
        raise DerivationError(
            "empty_support", "binary node with no child derivations"
        )
    if len(node) != 3:
        raise DerivationError("arity_mismatch", "binary node arity")
    left_claim, left_leaves, left_size = _typed_derivation(node[1])
    right_claim, right_leaves, right_size = _typed_derivation(node[2])
    if left_claim != BINARY_CHILD_CLAIMS[0]:
        raise DerivationError(
            "ill_typed_child",
            "left child derives " + left_claim + ", expected c0",
        )
    if right_claim != BINARY_CHILD_CLAIMS[1]:
        raise DerivationError(
            "ill_typed_child",
            "right child derives " + right_claim + ", expected c1",
        )
    return (
        "c2",
        left_leaves + right_leaves,
        1 + left_size + right_size,
    )


def check_derivation(node: object) -> tuple[str, tuple[str, ...], int]:
    """Validate a support object as a finite derivation."""
    _scan_cycles(node, frozenset())
    return _typed_derivation(node)


def enumerate_supports(claim: str) -> tuple:
    """Enumerate every finite derivation of `claim`, in a fixed order.

    The grammar is non-recursive apart from the binary c2 rule, so the
    derivation set of each claim is finite and small.
    """
    if claim not in CLAIM_IDS:
        return ()
    if claim in ("c0", "c1"):
        return tuple(rule for rule in LEAF_RULES if rule[0] == claim)
    derivations = []
    for left in enumerate_supports(BINARY_CHILD_CLAIMS[0]):
        for right in enumerate_supports(BINARY_CHILD_CLAIMS[1]):
            derivations.append(("c2", left, right))
    return tuple(derivations)


# ---------------------------------------------------------------------------
# 3. Policy, state and the acceptance rule
# ---------------------------------------------------------------------------


def valid_policy() -> dict:
    return {
        "policy_version": 1,
        "candidate_id": 7,
        "campaign_required": True,
        "required_actors": 2,
        "freshness_required": True,
        "archive_required": True,
        "required_premises": ["pA", "pB"],
    }


def valid_state() -> dict:
    return {
        "observed_policy_version": 1,
        "bound_candidate": 7,
        "reported_claim": EVALUATED_CLAIM,
        "present": {q: True for q in PREMISE_IDS},
        "challenged": {q: False for q in PREMISE_IDS},
        "revoked": {q: False for q in PREMISE_IDS},
        "campaign_closed": True,
        "independent_actors": 2,
        "transparency_fresh": True,
        "archive_present": True,
        "authenticated": True,
    }


def _flag(mapping: dict, premise: str) -> bool:
    return bool(mapping.get(premise, False))


def policy_check(policy: dict, state: dict) -> list[str]:
    """The policy half of the acceptance rule, as a list of refusal codes."""
    reasons: list[str] = []
    if policy.get("policy_version") != state.get("observed_policy_version"):
        reasons.append("policy_version_mismatch")
    if policy.get("candidate_id") != state.get("bound_candidate"):
        reasons.append("candidate_mismatch")
    if policy.get("campaign_required") and not state.get("campaign_closed"):
        reasons.append("campaign_not_closed")
    if not (
        int(policy.get("required_actors", 0)) <= int(state.get("independent_actors", 0))
    ):
        reasons.append("insufficient_independent_actors")
    if policy.get("freshness_required") and not state.get("transparency_fresh"):
        reasons.append("stale_transparency")
    if policy.get("archive_required") and not state.get("archive_present"):
        reasons.append("archive_missing")
    for premise in policy.get("required_premises", []):
        if premise not in PREMISE_IDS:
            reasons.append("required_premise_unknown:" + str(premise))
        elif not _flag(state.get("present", {}), premise):
            reasons.append("required_premise_absent:" + premise)
    return reasons


def support_check(state: dict, node: object, claim: str) -> list[str]:
    """The derivation half of the acceptance rule for one support object."""
    try:
        derived_claim, leaves, _size = check_derivation(node)
    except DerivationError as exc:
        return [exc.reason]
    if derived_claim != claim:
        return ["claim_index_mismatch:" + derived_claim + "_as_" + claim]
    reasons: list[str] = []
    for premise in leaves:
        if not _flag(state.get("present", {}), premise):
            reasons.append("premise_absent:" + premise)
        if _flag(state.get("challenged", {}), premise):
            reasons.append("premise_challenged:" + premise)
        if _flag(state.get("revoked", {}), premise):
            reasons.append("premise_revoked:" + premise)
    return reasons


def evaluate(
    policy: dict,
    state: dict,
    claim: str,
    supports: tuple | None = None,
) -> dict:
    """Decide acceptance by searching the finite support universe of `claim`."""
    reasons = policy_check(policy, state)
    if state.get("reported_claim") != claim:
        reasons.append("reported_claim_mismatch")

    if claim not in CLAIM_IDS:
        reasons.append("unknown_claim")
        supports = ()

    if supports is None:
        supports = enumerate_supports(claim)
    supports = tuple(supports)
    if not supports:
        reasons.append("no_support_available")

    # Acceptance is existential, matching the Coq model: one admissible finite
    # derivation of the claim is sufficient. A rejected alternative derivation
    # is recorded in supports_considered but does not by itself refuse the
    # claim. Only when no derivation is admissible are the individual support
    # reasons promoted to the top-level refusal record.
    admitted_support = None
    support_reasons = []
    rejected_support_reasons: list[str] = []
    for node in supports:
        node_reasons = support_check(state, node, claim)
        support_reasons.append(
            {"support": render(node), "reasons": sorted(set(node_reasons))}
        )
        rejected_support_reasons.extend(node_reasons)
        if not node_reasons and admitted_support is None:
            admitted_support = render(node)

    if supports and admitted_support is None:
        reasons.append("no_admissible_support")
        reasons.extend(rejected_support_reasons)

    reasons = sorted(set(reasons))
    return {
        "accepted": not reasons,
        "claim": claim,
        "reasons": reasons,
        "admitted_support": admitted_support,
        "supports_considered": support_reasons,
    }


def evaluate_with_derivation(
    policy: dict, state: dict, claim: str, node: object
) -> dict:
    """Decide acceptance when one specific support object is offered."""
    reasons = policy_check(policy, state)
    if state.get("reported_claim") != claim:
        reasons.append("reported_claim_mismatch")
    node_reasons = support_check(state, node, claim)
    reasons.extend(node_reasons)
    reasons = sorted(set(reasons))
    return {
        "accepted": not reasons,
        "claim": claim,
        "reasons": reasons,
        "admitted_support": None if reasons else render(node),
        "supports_considered": [
            {"support": render(node), "reasons": sorted(set(node_reasons))}
        ],
    }


# ---------------------------------------------------------------------------
# 4. Control definitions
# ---------------------------------------------------------------------------


def _p01_no_unsupported_support(policy: dict, state: dict):
    # Invariant 1: no admissible finite derivation exists for the claim.
    return policy, state, ()


def _p02_missing_mandatory_premise(policy: dict, state: dict):
    # Invariant 2: a required premise outside the derivation is absent.
    policy["required_premises"] = ["pA", "pB", "pD"]
    state["present"]["pD"] = False
    return policy, state, None


def _p03_candidate_substitution(policy: dict, state: dict):
    # Invariant 3: the bound candidate differs from the policy candidate.
    state["bound_candidate"] = 8
    return policy, state, None


def _p04_authenticated_but_unsupported(policy: dict, state: dict):
    # Invariant 4: a valid authentication flag with no admissible derivation.
    # The requirement list moves to premises the derivation does not use, so
    # the refusal can only come from the derivation's premise availability.
    policy["required_premises"] = ["pB", "pD"]
    state["present"]["pA"] = False
    state["present"]["pC"] = False
    return policy, state, None


def _p05_unrelated_proof(policy: dict, state: dict):
    # Invariant 5: the reported claim is not the claim under evaluation.
    state["reported_claim"] = "c0"
    return policy, state, None


def _p06_challenged_premise(policy: dict, state: dict):
    # Invariant 6: a premise present in every derivation of c2 is challenged.
    state["challenged"]["pB"] = True
    return policy, state, None


def _p07_revoked_premise(policy: dict, state: dict):
    # Invariant 7: a premise present in every derivation of c2 is revoked.
    state["revoked"]["pB"] = True
    return policy, state, None


def _p08_incomplete_campaign(policy: dict, state: dict):
    # Invariant 8: a required campaign is not closed.
    state["campaign_closed"] = False
    return policy, state, None


def _p09_duplicate_credentials(policy: dict, state: dict):
    # Invariant 9: independent actors below the declared threshold.
    state["independent_actors"] = 1
    return policy, state, None


def _p10_stale_transparency(policy: dict, state: dict):
    # Invariant 10: a required freshness condition is false.
    state["transparency_fresh"] = False
    return policy, state, None


def _p11_missing_archive(policy: dict, state: dict):
    # Invariant 11: a required archive is absent.
    state["archive_present"] = False
    return policy, state, None


def _p12_policy_version_substitution(policy: dict, state: dict):
    # Invariant 12: the declared policy version is not the observed version.
    policy["policy_version"] = 2
    return policy, state, None


PRIMARY_CONTROLS = (
    {
        "id": "p01_no_unsupported_support",
        "invariant": "no_unsupported_or_cyclic_admission",
        "mutation": (
            "Set the support universe of the evaluated claim to empty: no finite "
            "derivation is available. Policy and state are unchanged."
        ),
        "apply": _p01_no_unsupported_support,
        "expected_reasons": ("no_support_available",),
    },
    {
        "id": "p02_missing_mandatory_premise",
        "invariant": "missing_mandatory_evidence_blocks",
        "mutation": (
            "Add pD to policy.required_premises and mark pD absent. pD is not a "
            "leaf of any c2 derivation, so only the required-premise clause fires."
        ),
        "apply": _p02_missing_mandatory_premise,
        "expected_reasons": ("required_premise_absent:pD",),
    },
    {
        "id": "p03_candidate_substitution",
        "invariant": "candidate_substitution_invalidates",
        "mutation": "Bind the state to candidate 8 while the policy names candidate 7.",
        "apply": _p03_candidate_substitution,
        "expected_reasons": ("candidate_mismatch",),
    },
    {
        "id": "p04_authenticated_but_unsupported",
        "invariant": "authentication_is_not_semantic_support",
        "mutation": (
            "Keep authenticated = true, move required_premises to pB and pD, and "
            "remove the c0 leaf premises pA and pC. No c2 derivation is supported."
        ),
        "apply": _p04_authenticated_but_unsupported,
        "expected_reasons": ("premise_absent:pA", "premise_absent:pC"),
    },
    {
        "id": "p05_unrelated_proof",
        "invariant": "unrelated_proof_does_not_satisfy",
        "mutation": "Report claim c0 while the evaluated claim is c2.",
        "apply": _p05_unrelated_proof,
        "expected_reasons": ("reported_claim_mismatch",),
    },
    {
        "id": "p06_challenged_premise",
        "invariant": "challenged_premise_blocks",
        "mutation": "Challenge pB, which occurs in every finite derivation of c2.",
        "apply": _p06_challenged_premise,
        "expected_reasons": ("premise_challenged:pB",),
    },
    {
        "id": "p07_revoked_premise",
        "invariant": "revoked_premise_invalidates",
        "mutation": "Revoke pB, which occurs in every finite derivation of c2.",
        "apply": _p07_revoked_premise,
        "expected_reasons": ("premise_revoked:pB",),
    },
    {
        "id": "p08_incomplete_campaign",
        "invariant": "incomplete_campaign_blocks",
        "mutation": "Open the campaign while the policy requires it to be closed.",
        "apply": _p08_incomplete_campaign,
        "expected_reasons": ("campaign_not_closed",),
    },
    {
        "id": "p09_duplicate_credentials",
        "invariant": "duplicate_credentials_do_not_satisfy_independence",
        "mutation": (
            "Count one independent actor: duplicated credentials sit below the "
            "declared threshold of two."
        ),
        "apply": _p09_duplicate_credentials,
        "expected_reasons": ("insufficient_independent_actors",),
    },
    {
        "id": "p10_stale_transparency",
        "invariant": "stale_transparency_blocks",
        "mutation": "Mark transparency stale while the policy requires freshness.",
        "apply": _p10_stale_transparency,
        "expected_reasons": ("stale_transparency",),
    },
    {
        "id": "p11_missing_archive",
        "invariant": "missing_archive_blocks_reconstruction",
        "mutation": "Remove the archive while the policy requires it.",
        "apply": _p11_missing_archive,
        "expected_reasons": ("archive_missing",),
    },
    {
        "id": "p12_policy_version_substitution",
        "invariant": "policy_substitution_blocks",
        "mutation": "Declare policy version 2 while the state observed version 1.",
        "apply": _p12_policy_version_substitution,
        "expected_reasons": ("policy_version_mismatch",),
    },
)


# ---------------------------------------------------------------------------
# 5. Helpers for the control receipt
# ---------------------------------------------------------------------------


def _diff_fields(base: dict, mutated: dict, prefix: str) -> list[str]:
    fields = []
    for key in sorted(set(base) | set(mutated)):
        base_value = base.get(key)
        mutated_value = mutated.get(key)
        if isinstance(base_value, dict) and isinstance(mutated_value, dict):
            fields.extend(_diff_fields(base_value, mutated_value, prefix + "." + key))
        elif base_value != mutated_value:
            fields.append(prefix + "." + key)
    return fields


def _restore_field(target: dict, source: dict, parts: list[str]) -> None:
    """Set exactly one leaf field of target to its value in source."""
    target_node = target
    source_node = source
    for part in parts[:-1]:
        target_node = target_node[part]
        source_node = source_node[part]
    target_node[parts[-1]] = copy.deepcopy(source_node[parts[-1]])


def _premises_of(node: object) -> tuple[str, ...]:
    _claim, leaves, _size = check_derivation(node)
    return leaves


def _every_derivation_contains(claim: str, premise: str) -> bool:
    supports = enumerate_supports(claim)
    if not supports:
        return False
    return all(premise in _premises_of(node) for node in supports)


def _expected_met(expected: tuple[str, ...], observed: list[str]) -> bool:
    return all(
        any(reason == exp or reason.startswith(exp + ":") for reason in observed)
        for exp in expected
    )


class Ledger:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def record(
        self,
        ok: bool,
        family: str,
        control: str,
        kind: str,
        detail: str,
    ) -> bool:
        self.checks.append(
            {
                "family": family,
                "control": control,
                "kind": kind,
                "status": "PASS" if ok else "FAIL",
                "detail": detail,
            }
        )
        return ok

    def lines(self) -> list[str]:
        lines = []
        for check in self.checks:
            lines.append(
                "%s %s/%s %s %s"
                % (
                    check["status"],
                    check["family"],
                    check["control"],
                    check["kind"],
                    check["detail"],
                )
            )
        return lines

    def count(self, kind: str) -> int:
        return sum(1 for check in self.checks if check["kind"] == kind)

    def failures(self) -> int:
        return sum(1 for check in self.checks if check["status"] == "FAIL")


# ---------------------------------------------------------------------------
# 6. Control execution
# ---------------------------------------------------------------------------


def run_positive(ledger: Ledger) -> dict:
    policy = valid_policy()
    state = valid_state()
    result = evaluate(policy, state, EVALUATED_CLAIM)
    ok = result["accepted"] and result["admitted_support"] == render(VALID_DERIVATION)
    ledger.record(
        ok,
        "positive",
        "valid_policy_state_derivation",
        "positive_admission",
        "admitted support=%s authenticated=%s"
        % (result["admitted_support"], state["authenticated"]),
    )
    return {
        "family": "positive",
        "id": "valid_policy_state_derivation",
        "purpose": (
            "One fully valid policy, state and finite derivation must be admitted, "
            "so the negative controls constrain a non-vacuous predicate. "
            "authenticated is true and plays no role in the decision."
        ),
        "policy": policy,
        "state": state,
        "derivation": render(VALID_DERIVATION),
        "derivation_leaves": list(_premises_of(VALID_DERIVATION)),
        "expected": "admitted",
        "observed": "admitted" if result["accepted"] else "refused",
        "observed_reasons": result["reasons"],
        "status": "PASS" if ok else "FAIL",
    }


def run_primary_control(ledger: Ledger, spec: dict) -> dict:
    base_policy = valid_policy()
    base_state = valid_state()
    policy, state, supports = spec["apply"](base_policy, base_state)

    mutation_fields = _diff_fields(valid_policy(), policy, "policy")
    mutation_fields += _diff_fields(valid_state(), state, "state")
    if supports is not None:
        mutation_fields.append("supports(" + EVALUATED_CLAIM + ")")

    mutated = evaluate(policy, state, EVALUATED_CLAIM, supports=supports)
    refusal_ok = (not mutated["accepted"]) and _expected_met(
        spec["expected_reasons"], mutated["reasons"]
    )
    ledger.record(
        refusal_ok,
        "primary",
        spec["id"],
        "primary_refusal",
        "refused reasons=" + ",".join(mutated["reasons"]),
    )

    # Restoration: start from the mutated policy/state and undo exactly the
    # fields recorded in mutation_fields. This is not a re-run of the positive
    # control; it proves the refusal is reversed by that mutation alone.
    restored_policy = copy.deepcopy(policy)
    restored_state = copy.deepcopy(state)
    restored_supports = supports
    for field in mutation_fields:
        if field.startswith("supports("):
            restored_supports = None
            continue
        scope, *parts = field.split(".")
        if scope == "policy":
            _restore_field(restored_policy, valid_policy(), parts)
        elif scope == "state":
            _restore_field(restored_state, valid_state(), parts)
        else:
            raise AssertionError("unknown mutation field: " + field)

    fully_restored = (
        restored_policy == valid_policy()
        and restored_state == valid_state()
        and restored_supports is None
    )
    restored = evaluate(
        restored_policy,
        restored_state,
        EVALUATED_CLAIM,
        supports=restored_supports,
    )
    restoration_ok = (
        fully_restored and restored["accepted"] and not restored["reasons"]
    )
    ledger.record(
        restoration_ok,
        "primary",
        spec["id"],
        "restoration",
        "restored_fields="
        + ",".join(mutation_fields)
        + " admitted support="
        + str(restored["admitted_support"]),
    )

    record = {
        "family": "primary",
        "id": spec["id"],
        "invariant": spec["invariant"],
        "mutation": spec["mutation"],
        "mutation_fields": mutation_fields,
        "expected": "refused",
        "expected_reasons": list(spec["expected_reasons"]),
        "observed": "admitted" if mutated["accepted"] else "refused",
        "observed_reasons": mutated["reasons"],
        "supports_considered": mutated["supports_considered"],
        "status": "PASS" if refusal_ok else "FAIL",
        "restoration": {
            "mutation": "Restore only the mutated field(s) to the valid value.",
            "restored_fields": mutation_fields,
            "exactly_base_after_restoration": fully_restored,
            "expected": "admitted",
            "observed": "admitted" if restored["accepted"] else "refused",
            "observed_reasons": restored["reasons"],
            "status": "PASS" if restoration_ok else "FAIL",
        },
    }
    if spec["id"] in ("p06_challenged_premise", "p07_revoked_premise"):
        record["premise_occurs_in_every_derivation_of_" + EVALUATED_CLAIM] = (
            _every_derivation_contains(EVALUATED_CLAIM, "pB")
        )
    return record


def run_structural_controls(ledger: Ledger) -> list[dict]:
    records = []

    # (a) A support object with an empty leaf set is not a derivation.
    empty_support = ("c2",)
    result_a = evaluate_with_derivation(
        valid_policy(), valid_state(), EVALUATED_CLAIM, empty_support
    )
    ok_a = (not result_a["accepted"]) and _expected_met(
        ("empty_support",), result_a["reasons"]
    )
    # The grammar has no zero-leaf inhabitant; verify that directly.
    min_leaves = min(
        len(_premises_of(node))
        for claim in CLAIM_IDS
        for node in enumerate_supports(claim)
    )
    ok_a = ok_a and min_leaves >= 1
    ledger.record(
        ok_a,
        "structural",
        "s01_empty_leaf_set",
        "structural_refusal",
        "refused reasons=%s min_leaves_in_grammar=%d"
        % (",".join(result_a["reasons"]), min_leaves),
    )
    restoration_a = evaluate_with_derivation(
        valid_policy(), valid_state(), EVALUATED_CLAIM, VALID_DERIVATION
    )
    ok_a_restore = restoration_a["accepted"]
    ledger.record(
        ok_a_restore,
        "structural",
        "s01_empty_leaf_set",
        "structural_restoration",
        "admitted support=" + str(restoration_a["admitted_support"]),
    )
    records.append(
        {
            "family": "structural",
            "id": "s01_empty_leaf_set",
            "purpose": (
                "A support object whose leaf set is empty cannot be admitted. The "
                "declared grammar has no zero-leaf constructor; an injected empty "
                "binary node is refused by well-formedness."
            ),
            "mutation": "Offer the support object ('c2',) with no child derivations.",
            "expected": "refused",
            "expected_reasons": ["empty_support"],
            "observed": "admitted" if result_a["accepted"] else "refused",
            "observed_reasons": result_a["reasons"],
            "grammar_minimum_leaf_count": min_leaves,
            "status": "PASS" if ok_a else "FAIL",
            "restoration": {
                "mutation": "Offer the finite well-typed c2 derivation instead.",
                "expected": "admitted",
                "observed": "admitted" if restoration_a["accepted"] else "refused",
                "status": "PASS" if ok_a_restore else "FAIL",
            },
        }
    )

    # (b) A cyclic support object is not a finite derivation.
    marker = ("cycle", "c0")
    result_marker = evaluate_with_derivation(
        valid_policy(), valid_state(), EVALUATED_CLAIM, marker
    )
    ok_marker = (not result_marker["accepted"]) and _expected_met(
        ("cyclic_marker_not_finite",), result_marker["reasons"]
    )
    ledger.record(
        ok_marker,
        "structural",
        "s02_cyclic_support_marker",
        "structural_refusal",
        "explicit marker refused reasons=" + ",".join(result_marker["reasons"]),
    )

    # A genuinely self-referential, finitely sized object graph: a list that
    # contains itself. It is refused without ever being unfolded infinitely.
    loop: list = []
    loop.append(loop)
    self_referential = ("c2", ("c0", "pA"), loop)
    result_loop = evaluate_with_derivation(
        valid_policy(), valid_state(), EVALUATED_CLAIM, self_referential
    )
    ok_loop = (not result_loop["accepted"]) and _expected_met(
        ("cyclic_marker_not_finite",), result_loop["reasons"]
    )
    ledger.record(
        ok_loop,
        "structural",
        "s02_cyclic_support_marker",
        "structural_refusal_self_reference",
        "self-referential object refused reasons=" + ",".join(result_loop["reasons"]),
    )

    restoration_b = evaluate_with_derivation(
        valid_policy(), valid_state(), EVALUATED_CLAIM, VALID_DERIVATION
    )
    ok_b_restore = restoration_b["accepted"]
    ledger.record(
        ok_b_restore,
        "structural",
        "s02_cyclic_support_marker",
        "structural_restoration",
        "admitted support=" + str(restoration_b["admitted_support"]),
    )
    records.append(
        {
            "family": "structural",
            "id": "s02_cyclic_support_marker",
            "purpose": (
                "A claim whose only support is self-referential is refused as not "
                "a finite derivation. Both an explicit ('cycle', 'c0') marker and "
                "a finitely sized self-referential list are refused; no infinite "
                "object is constructed."
            ),
            "mutation": (
                "Offer ('cycle', 'c0'); then offer ('c2', ('c0', 'pA'), x) where "
                "the list x contains itself."
            ),
            "expected": "refused",
            "expected_reasons": ["cyclic_marker_not_finite"],
            "observed_marker": result_marker["reasons"],
            "observed_self_referential": {
                "support": render(self_referential),
                "reasons": result_loop["reasons"],
            },
            "status": "PASS" if (ok_marker and ok_loop) else "FAIL",
            "restoration": {
                "mutation": "Offer the finite well-typed c2 derivation instead.",
                "expected": "admitted",
                "observed": "admitted" if restoration_b["accepted"] else "refused",
                "status": "PASS" if ok_b_restore else "FAIL",
            },
        }
    )

    # (c) The claim index is part of the support type: a derivation of one
    # claim is not a derivation of another.
    offered_other = ("c1", "pB")
    result_other = evaluate_with_derivation(
        valid_policy(), valid_state(), EVALUATED_CLAIM, offered_other
    )
    ok_other = (not result_other["accepted"]) and _expected_met(
        ("claim_index_mismatch",), result_other["reasons"]
    )
    ledger.record(
        ok_other,
        "structural",
        "s03_claim_index_mismatch",
        "structural_refusal",
        "offered c1 derivation for c2 reasons=" + ",".join(result_other["reasons"]),
    )

    swapped_children = ("c2", ("c1", "pB"), ("c0", "pA"))
    result_swapped = evaluate_with_derivation(
        valid_policy(), valid_state(), EVALUATED_CLAIM, swapped_children
    )
    ok_swapped = (not result_swapped["accepted"]) and _expected_met(
        ("ill_typed_child",), result_swapped["reasons"]
    )
    ledger.record(
        ok_swapped,
        "structural",
        "s03_claim_index_mismatch",
        "structural_refusal_ill_typed_child",
        "swapped children reasons=" + ",".join(result_swapped["reasons"]),
    )

    restoration_c = evaluate_with_derivation(
        valid_policy(), valid_state(), EVALUATED_CLAIM, VALID_DERIVATION
    )
    ok_c_restore = restoration_c["accepted"]
    ledger.record(
        ok_c_restore,
        "structural",
        "s03_claim_index_mismatch",
        "structural_restoration",
        "admitted support=" + str(restoration_c["admitted_support"]),
    )
    records.append(
        {
            "family": "structural",
            "id": "s03_claim_index_mismatch",
            "purpose": (
                "The claim index is part of the support type: a c1 derivation "
                "offered for c2, or a binary node with swapped children, is not a "
                "derivation of the evaluated claim."
            ),
            "mutation": (
                "Offer ('c1', 'pB') for claim c2; then offer "
                "('c2', ('c1', 'pB'), ('c0', 'pA'))."
            ),
            "expected": "refused",
            "expected_reasons": ["claim_index_mismatch", "ill_typed_child"],
            "observed_other_claim": result_other["reasons"],
            "observed_swapped_children": result_swapped["reasons"],
            "status": "PASS" if (ok_other and ok_swapped) else "FAIL",
            "restoration": {
                "mutation": "Offer the finite well-typed c2 derivation instead.",
                "expected": "admitted",
                "observed": "admitted" if restoration_c["accepted"] else "refused",
                "status": "PASS" if ok_c_restore else "FAIL",
            },
        }
    )

    # (d) Acceptance is existential, matching admitted in the Coq model: one
    # admissible derivation is sufficient, and a rejected alternative support
    # does not veto it. Removing pA leaves the c0-from-pC derivation available.
    alt_policy = valid_policy()
    alt_policy["required_premises"] = ["pB", "pC"]
    alt_state = valid_state()
    alt_state["present"]["pA"] = False
    alt_support = render(("c2", ("c0", "pC"), ("c1", "pB")))
    result_alt = evaluate(alt_policy, alt_state, EVALUATED_CLAIM)
    ok_alt = result_alt["accepted"] and result_alt["admitted_support"] == alt_support
    ledger.record(
        ok_alt,
        "structural",
        "s04_alternative_support",
        "structural_admission",
        "admitted support=" + str(result_alt["admitted_support"]),
    )

    # Inverse: also remove pC. Every c2 derivation now has an absent leaf, so
    # the same existential rule must refuse.
    alt_state_inverse = copy.deepcopy(alt_state)
    alt_state_inverse["present"]["pC"] = False
    result_alt_none = evaluate(alt_policy, alt_state_inverse, EVALUATED_CLAIM)
    ok_alt_none = (not result_alt_none["accepted"]) and _expected_met(
        ("no_admissible_support",), result_alt_none["reasons"]
    )
    ledger.record(
        ok_alt_none,
        "structural",
        "s04_alternative_support",
        "structural_refusal_alternative_absent",
        "refused reasons=" + ",".join(result_alt_none["reasons"]),
    )

    # Restoration: pA and pC present again, required premises back to the base.
    restored_alt_state = copy.deepcopy(alt_state_inverse)
    restored_alt_state["present"]["pA"] = True
    restored_alt_state["present"]["pC"] = True
    result_alt_restore = evaluate(
        valid_policy(), restored_alt_state, EVALUATED_CLAIM
    )
    ok_alt_restore = result_alt_restore["accepted"] and (
        restored_alt_state == valid_state()
    )
    ledger.record(
        ok_alt_restore,
        "structural",
        "s04_alternative_support",
        "structural_restoration",
        "admitted support=" + str(result_alt_restore["admitted_support"]),
    )

    records.append(
        {
            "family": "structural",
            "id": "s04_alternative_support",
            "purpose": (
                "Acceptance is existential: a claim with one admissible finite "
                "derivation is admitted even though another derivation of the same "
                "claim is rejected. With pA absent and pC present, c2 is admitted "
                "via the c0-from-pC support; removing pC as well refuses."
            ),
            "mutation": (
                "Required premises [pB,pC]; pA absent, pC present; then pC also "
                "absent."
            ),
            "expected": "admitted",
            "expected_inverse": "refused",
            "observed_admitted_support": result_alt["admitted_support"],
            "observed_alternative_support_status": "PASS" if ok_alt else "FAIL",
            "observed_inverse_reasons": result_alt_none["reasons"],
            "observed_inverse_status": "PASS" if ok_alt_none else "FAIL",
            "status": "PASS" if (ok_alt and ok_alt_none) else "FAIL",
            "restoration": {
                "mutation": "Restore pA and pC and the base required premises.",
                "expected": "admitted",
                "observed": "admitted" if result_alt_restore["accepted"] else "refused",
                "status": "PASS" if ok_alt_restore else "FAIL",
            },
        }
    )

    return records


# ---------------------------------------------------------------------------
# 7. Receipt
# ---------------------------------------------------------------------------


def build_receipt() -> tuple[dict, list[str], int]:
    ledger = Ledger()
    positive = run_positive(ledger)
    primary = [run_primary_control(ledger, spec) for spec in PRIMARY_CONTROLS]
    structural = run_structural_controls(ledger)

    universe = []
    for claim in CLAIM_IDS:
        for node in enumerate_supports(claim):
            derived, leaves, size = check_derivation(node)
            universe.append(
                {
                    "claim": derived,
                    "support": render(node),
                    "leaves": list(leaves),
                    "size": size,
                }
            )

    totals = {
        "controls": 1 + len(primary) + len(structural),
        "checks": len(ledger.checks),
        "passed": len(ledger.checks) - ledger.failures(),
        "failed": ledger.failures(),
        "positive_admissions": ledger.count("positive_admission"),
        "primary_controls": len(primary),
        "primary_refusals": ledger.count("primary_refusal"),
        "primary_restorations": ledger.count("restoration"),
        "structural_controls": len(structural),
        "structural_refusals": sum(
            1
            for check in ledger.checks
            if check["kind"].startswith("structural_refusal")
        ),
        "structural_admissions": ledger.count("structural_admission"),
        "structural_restorations": ledger.count("structural_restoration"),
    }

    receipt = {
        "schema": SCHEMA_ID,
        "phase": "16.1b",
        "evidence_kind": "EXECUTED_MODEL",
        "model": {
            "description": (
                "Independent executable model of the finite ETP acceptance "
                "predicate. Premises pA,pB,pC,pD; claims c0,c1,c2; derivations "
                "are finite nested tuples built from the four declared rules; "
                "support is enumerated per claim."
            ),
            "premise_ids": list(PREMISE_IDS),
            "claim_ids": list(CLAIM_IDS),
            "derivation_grammar": [
                '("c0", "pA")   c0 from pA',
                '("c1", "pB")   c1 from pB',
                '("c0", "pC")   c0 from pC',
                '("c2", d0, d1) c2 from a c0 derivation and a c1 derivation',
            ],
            "acceptance_rule": (
                "policy_satisfied(policy, state) AND state.reported_claim == claim "
                "AND the offered/enumerated finite derivation of claim exists and "
                "every premise of it is present, unchallenged and unrevoked. "
                "Authentication is not a condition."
            ),
            "evaluated_claim": EVALUATED_CLAIM,
            "derivation_universe": universe,
            "derivation_universe_size": len(universe),
        },
        "claim_ceiling": CLAIM_CEILING,
        "non_claims": list(NON_CLAIMS),
        "positive_control": positive,
        "controls": primary + structural,
        "totals": totals,
    }
    return receipt, ledger.lines(), ledger.failures()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independent executable adversarial-control oracle for the finite "
            "ETP acceptance model."
        )
    )
    parser.add_argument(
        "--out",
        required=True,
        help="path of the deterministic JSON receipt to write",
    )
    args = parser.parse_args(argv)

    receipt, lines, failures = build_receipt()
    payload = json.dumps(receipt, sort_keys=True, indent=2) + "\n"

    for line in lines:
        sys.stderr.write(line + "\n")
    totals = receipt["totals"]
    sys.stderr.write(
        "TOTALS controls=%d checks=%d passed=%d failed=%d primary=%d "
        "primary_refused=%d primary_restorations=%d structural=%d "
        "structural_refusals=%d structural_admissions=%d "
        "structural_restorations=%d\n"
        % (
            totals["controls"],
            totals["checks"],
            totals["passed"],
            totals["failed"],
            totals["primary_controls"],
            totals["primary_refusals"],
            totals["primary_restorations"],
            totals["structural_controls"],
            totals["structural_refusals"],
            totals["structural_admissions"],
            totals["structural_restorations"],
        )
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(payload, encoding="utf-8", newline="\n")
    sys.stdout.write(payload)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
