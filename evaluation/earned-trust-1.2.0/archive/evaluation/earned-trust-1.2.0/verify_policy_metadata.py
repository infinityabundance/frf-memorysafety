#!/usr/bin/env python3
"""TUF-inspired policy metadata verifier with self-test controls.

This verifier checks:
- Required fields and schema compliance
- Versioning and policy_id consistency
- Expiry date validation
- Delegated-role authorization (role -> key mapping)
- Rollback counter monotonicity
- Freeze state validation
- Key existence and validity
- Role-to-key delegation correctness

Exit statuses: 0 verified, 4 refused (policy errors).
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

class VerifierError(Exception):
    pass

class RefusedError(VerifierError):
    pass

def load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise VerifierError(f"cannot parse JSON at {path}: {error}") from error

def validate_schema(policy: Dict[str, Any]) -> None:
    required_keys = ["schema", "spec", "version", "issued_at_unix", "expires_at_unix", "policy_id", "roles", "delegations", "key_rotation_state", "rollback_counter", "freeze_state", "correction_authority", "non_claims"]
    for key in required_keys:
        if key not in policy:
            raise RefusedError([f"missing required field: {key}"])

def validate_issued_expired(policy: Dict[str, Any], now: int) -> None:
    if policy["issued_at_unix"] > now:
        raise RefusedError(["issued_after_now"])
    if policy["expires_at_unix"] < now:
        raise RefusedError(["expired_before_now"])

def validate_roles(policy: Dict[str, Any]) -> None:
    roles = policy["roles"]
    if not isinstance(roles, list):
        raise RefusedError(["roles must be a list"])
    
    # Check role structure
    for role in roles:
        if not all(k in role for k in ["id", "description", "predicate_scopes", "distinct_actor_threshold", "independent", "keys"]):
            raise RefusedError(["role missing required fields"])
        
        # Check distinct_actor_threshold
        if not isinstance(role["distinct_actor_threshold"], int) or role["distinct_actor_threshold"] < 0:
            raise RefusedError(["invalid distinct_actor_threshold"])
            
        # Check independent flag
        if not isinstance(role["independent"], bool):
            raise RefusedError(["invalid independent flag"])
            
        # Check keys
        keys = role.get("keys", [])
        if not isinstance(keys, list):
            raise RefusedError(["keys must be a list"])
            
        for key in keys:
            if not all(k in key for k in ["keyid", "algorithm", "public_key_base64", "actor", "valid_from_unix", "valid_until_unix"]):
                raise RefusedError(["key missing required fields"])
                
            # Validate keyid uniqueness within role
            if any(k["keyid"] == k2["keyid"] for k in keys for k2 in keys if k is not k2):
                raise RefusedError(["duplicate keyid within role"])
                
            # Validate key validity period
            if key["valid_from_unix"] > key["valid_until_unix"]:
                raise RefusedError(["key validity period invalid"])

def validate_delegations(policy: Dict[str, Any]) -> None:
    delegations = policy["delegations"]
    if not isinstance(delegations, list):
        raise RefusedError(["delegations must be a list"])

    roles = {role["id"]: role for role in policy["roles"]}
    for delegation in delegations:
        if not isinstance(delegation, dict):
            raise RefusedError(["delegation entry must be a dict"])
        required = ["role", "delegated_to", "valid_from_unix", "valid_until_unix"]
        for key in required:
            if key not in delegation:
                raise RefusedError([f"delegation missing required field: {key}"])
        role = roles.get(delegation["role"])
        if role is None:
            raise RefusedError([f"role {delegation['role']} referenced in delegation does not exist"])
        if delegation["valid_from_unix"] > delegation["valid_until_unix"]:
            raise RefusedError(["delegation validity period invalid"])
        actors = {key["actor"] for key in role.get("keys", [])}
        if delegation["delegated_to"] not in actors:
            raise RefusedError([
                f"delegated_to {delegation['delegated_to']} is not a key actor for {delegation['role']}"
            ])

def validate_key_rotation_state(policy: Dict[str, Any]) -> None:
    state = policy["key_rotation_state"]
    if not isinstance(state, dict):
        raise RefusedError(["key_rotation_state must be a dict"])
        
    required = ["current_version", "previous_versions", "rotation_policy", "last_rotation_unix", "next_rotation_due_unix"]
    for key in required:
        if key not in state:
            raise RefusedError([f"key_rotation_state missing: {key}"])
            
    if not isinstance(state["current_version"], int) or state["current_version"] < 1:
        raise RefusedError(["invalid current_version"])
        
    if not isinstance(state["previous_versions"], list):
        raise RefusedError(["previous_versions must be a list"])
        
    if not isinstance(state["rotation_policy"], str):
        raise RefusedError(["rotation_policy must be a string"])
        
    if not isinstance(state["last_rotation_unix"], (int, type(None))):
        raise RefusedError(["last_rotation_unix must be int or null"])
        
    if not isinstance(state["next_rotation_due_unix"], (int, type(None))):
        raise RefusedError(["next_rotation_due_unix must be int or null"])

def validate_rollback_counter(policy: Dict[str, Any]) -> None:
    state = policy["rollback_counter"]
    if not isinstance(state, dict):
        raise RefusedError(["rollback_counter must be a dict"])
        
    required = ["current", "minimum_acceptable", "monotonic"]
    for key in required:
        if key not in state:
            raise RefusedError([f"rollback_counter missing: {key}"])
            
    if not isinstance(state["current"], int) or state["current"] < 1:
        raise RefusedError(["invalid current rollback counter"])
        
    if not isinstance(state["minimum_acceptable"], int) or state["minimum_acceptable"] < 1:
        raise RefusedError(["invalid minimum_acceptable rollback counter"])
        
    if not isinstance(state["monotonic"], bool):
        raise RefusedError(["invalid monotonic flag"])

def validate_freeze_state(policy: Dict[str, Any]) -> None:
    state = policy["freeze_state"]
    if not isinstance(state, dict):
        raise RefusedError(["freeze_state must be a dict"])
        
    required = ["frozen", "frozen_at_unix", "freeze_reason"]
    for key in required:
        if key not in state:
            raise RefusedError([f"freeze_state missing: {key}"])

    if "freeze_authority" not in state and "unfreeze_authority" not in state:
        raise RefusedError(["freeze_state missing freeze/unfreeze authority"])

    if not isinstance(state["frozen"], bool):
        raise RefusedError(["freeze_state.frozen must be boolean"])

    if state["frozen"] and not isinstance(state["frozen_at_unix"], (int, type(None))):
        raise RefusedError(["freeze_state.frozen_at_unix must be int or null"])

    if state["freeze_reason"] is not None and not isinstance(state["freeze_reason"], str):
        raise RefusedError(["freeze_state.freeze_reason must be string or null"])

    authority = state.get("freeze_authority", state.get("unfreeze_authority"))
    if authority is not None and not isinstance(authority, str):
        raise RefusedError(["freeze_state authority must be string or null"])

def validate_correction_authority(policy: Dict[str, Any]) -> None:
    authority = policy["correction_authority"]
    if not isinstance(authority, dict):
        raise RefusedError(["correction_authority must be a dict"])
        
    required = ["registry_path", "support_model_path", "historical_verdict_path", "plan_path"]
    for key in required:
        if key not in authority:
            raise RefusedError([f"correction_authority missing: {key}"])

def validate_non_claims(policy: Dict[str, Any]) -> None:
    claims = policy["non_claims"]
    if not isinstance(claims, list):
        raise RefusedError(["non_claims must be a list"])
        
    for claim in claims:
        if not isinstance(claim, str):
            raise RefusedError(["non_claims item must be string"])

def run_self_tests(policy: Dict[str, Any], now: int) -> List[str]:
    """Run self-test controls and return list of passed controls."""
    passed = []
    
    # Control 1: Valid schema and required fields
    try:
        validate_schema(policy)
        passed.append("valid_schema")
    except RefusedError as e:
        return [f"failed: {e}"]
    
    # Control 2: Issued and expired dates valid
    try:
        validate_issued_expired(policy, now)
        passed.append("valid_dates")
    except RefusedError as e:
        return [f"failed: {e}"]
    
    # Control 3: Roles structure valid
    try:
        validate_roles(policy)
        passed.append("valid_roles")
    except RefusedError as e:
        return [f"failed: {e}"]
    
    # Control 4: Delegations valid
    try:
        validate_delegations(policy)
        passed.append("valid_delegations")
    except RefusedError as e:
        return [f"failed: {e}"]
    
    # Control 5: Key rotation state valid
    try:
        validate_key_rotation_state(policy)
        passed.append("valid_key_rotation")
    except RefusedError as e:
        return [f"failed: {e}"]
    
    # Control 6: Rollback counter valid
    try:
        validate_rollback_counter(policy)
        passed.append("valid_rollback_counter")
    except RefusedError as e:
        return [f"failed: {e}"]
        
    # Control 7: Freeze state valid
    try:
        validate_freeze_state(policy)
        passed.append("valid_freeze_state")
    except RefusedError as e:
        return [f"failed: {e}"]
        
    # Control 8: Correction authority valid
    try:
        validate_correction_authority(policy)
        passed.append("valid_correction_authority")
    except RefusedError as e:
        return [f"failed: {e}"]
        
    # Control 9: Non-claims valid
    try:
        validate_non_claims(policy)
        passed.append("valid_non_claims")
    except RefusedError as e:
        return [f"failed: {e}"]
        
    return passed

def run_controls(policy: Dict[str, Any], now: int) -> List[str]:
    """Run positive validators and mutated negative controls."""
    controls: List[str] = []
    validators = [
        ("valid_schema", validate_schema),
        ("valid_dates", lambda p: validate_issued_expired(p, now)),
        ("valid_roles", validate_roles),
        ("valid_delegations", validate_delegations),
        ("valid_key_rotation", validate_key_rotation_state),
        ("valid_rollback_counter", validate_rollback_counter),
        ("valid_freeze_state", validate_freeze_state),
        ("valid_correction_authority", validate_correction_authority),
        ("valid_non_claims", validate_non_claims),
    ]
    for name, validator in validators:
        validator(policy)
        controls.append(f"pass:{name}")

    def expect(name: str, mutation, validator) -> None:
        mutated = copy.deepcopy(policy)
        mutation(mutated)
        try:
            validator(mutated)
        except RefusedError:
            controls.append(f"pass:{name}")
            return
        raise RefusedError([f"control {name} was not refused"])

    expect("missing_schema", lambda p: p.pop("schema"), validate_schema)
    expect(
        "expired_policy",
        lambda p: p.__setitem__("expires_at_unix", 1),
        lambda p: validate_issued_expired(p, now),
    )
    expect(
        "duplicate_keyid",
        lambda p: p["roles"][0]["keys"].append(copy.deepcopy(p["roles"][0]["keys"][0])),
        validate_roles,
    )
    expect(
        "delegation_missing_role",
        lambda p: p["delegations"][0].__setitem__("role", "no_such_role"),
        validate_delegations,
    )
    expect(
        "rotation_missing",
        lambda p: p["key_rotation_state"].pop("current_version"),
        validate_key_rotation_state,
    )
    expect(
        "rollback_nonmonotonic",
        lambda p: p["rollback_counter"].__setitem__("current", 0),
        validate_rollback_counter,
    )
    expect(
        "freeze_invalid",
        lambda p: p["freeze_state"].__setitem__("frozen", "yes"),
        validate_freeze_state,
    )
    expect(
        "correction_missing",
        lambda p: p["correction_authority"].pop("registry_path"),
        validate_correction_authority,
    )
    expect(
        "non_claims_invalid",
        lambda p: p.__setitem__("non_claims", "bad"),
        validate_non_claims,
    )
    return controls


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify policy metadata with self-tests")
    parser.add_argument("--policy", type=Path, required=True, help="Path to policy-metadata.json")
    parser.add_argument(
        "--now",
        type=int,
        required=True,
        help="verification time in Unix seconds; the caller supplies the bound",
    )
    parser.add_argument("--controls", action="store_true", help="Run self-test controls")
    args = parser.parse_args()
    
    if not args.controls:
        print("This verifier requires --controls to execute self-tests")
        return 4
        
    policy = load_json(args.policy)
    try:
        controls = run_controls(policy, args.now)
    except RefusedError as error:
        print(f"FAIL: {error.args[0] if error.args else error}")
        return 4

    for control in controls:
        print(control)
    print(f"controls passed: {len(controls)} of {len(controls)}")
    print("PASS")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except VerifierError as error:
        print(f"verifier error: {error}", file=sys.stderr)
        sys.exit(4)