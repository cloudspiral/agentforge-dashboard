"""Versioned safe fuzz corpus and deterministic FuzzPlanV2 expansion."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from agentforge.contracts.v1 import (
    ActionTypeV1,
    AttackActionV1,
    FuzzMutationOperatorV2,
    FuzzPlanV2,
    InvokeApprovedApiRequestActionV1,
    ProposedAttackV1,
    SendChatMessageActionV1,
    WaitForResponseActionV1,
)


class FuzzCatalogModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FuzzCorpusEntryV1(FuzzCatalogModel):
    corpus_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    payload_kind: Literal["text", "field_name", "json_value"]
    value: JsonValue
    operators: list[FuzzMutationOperatorV2] = Field(min_length=1, max_length=8)
    description: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def payload_matches_kind(self) -> FuzzCorpusEntryV1:
        if self.payload_kind in {"text", "field_name"} and not isinstance(self.value, str):
            raise ValueError("text and field-name corpus values must be strings")
        if len(self.operators) != len(set(self.operators)):
            raise ValueError("corpus operators must be unique")
        return self


class FuzzCorpusV1(FuzzCatalogModel):
    schema_version: Literal["1.0"]
    corpus_version: str = Field(min_length=1, max_length=128)
    entries: list[FuzzCorpusEntryV1] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def entry_ids_are_unique(self) -> FuzzCorpusV1:
        ids = [entry.corpus_id for entry in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("fuzz corpus IDs must be unique")
        return self


class ExpandedFuzzVariantV2(FuzzCatalogModel):
    schema_version: Literal["v2"] = "v2"
    variant_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    variant_index: int = Field(ge=0, le=5)
    operator_id: FuzzMutationOperatorV2
    corpus_id: str = Field(min_length=1, max_length=128)
    rng_seed: int = Field(ge=0, le=2**32 - 1)
    exact_payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    proposal: ProposedAttackV1


class MinimizedFuzzCandidateV2(FuzzCatalogModel):
    schema_version: Literal["v2"] = "v2"
    candidate_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    candidate_index: int = Field(ge=0, le=2)
    parent_payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_payload_bytes: int = Field(gt=0)
    candidate_payload_bytes: int = Field(gt=0)
    proposal: ProposedAttackV1

    @model_validator(mode="after")
    def candidate_is_strictly_smaller(self) -> MinimizedFuzzCandidateV2:
        if self.candidate_payload_bytes >= self.original_payload_bytes:
            raise ValueError("minimization candidates must be strictly smaller")
        return self


def load_fuzz_corpus(path: Path) -> FuzzCorpusV1:
    return FuzzCorpusV1.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _bounded_text(value: JsonValue) -> str:
    if not isinstance(value, str):
        raise ValueError("selected fuzz operator requires a text corpus entry")
    if "\x00" in value:
        raise ValueError("fuzz corpus text cannot contain NUL bytes")
    return value


def _mutate_chat(
    action: SendChatMessageActionV1,
    *,
    operator: FuzzMutationOperatorV2,
    entry: FuzzCorpusEntryV1,
) -> list[AttackActionV1]:
    fragment = _bounded_text(entry.value)
    if operator == FuzzMutationOperatorV2.APPEND_FRAGMENT:
        message = f"{action.message}{fragment}"
    elif operator == FuzzMutationOperatorV2.PREPEND_FRAGMENT:
        message = f"{fragment}{action.message}"
    elif operator == FuzzMutationOperatorV2.REPLACE_VALUE:
        message = fragment
    elif operator == FuzzMutationOperatorV2.SPLIT_MULTI_TURN:
        pivot = max(1, len(action.message) // 2)
        first = action.model_copy(
            update={
                "action_id": f"{action.action_id}-a",
                "message": action.message[:pivot],
                "description": f"{action.description} (split part one)",
            }
        )
        wait = WaitForResponseActionV1(
            action_id=f"{action.action_id}-a-wait",
            action_type=ActionTypeV1.WAIT_FOR_RESPONSE,
            description="Bounded wait between deterministic split fuzz turns",
            timeout_seconds=60.0,
            expected_event="copilot_response_complete",
        )
        second = action.model_copy(
            update={
                "action_id": f"{action.action_id}-b",
                "message": f"{action.message[pivot:]}{fragment}",
                "description": f"{action.description} (split part two)",
            }
        )
        return [first, wait, second]
    else:
        raise ValueError("operator is not supported for a chat-message mutation point")
    if len(message.encode("utf-8")) > 4_000:
        raise ValueError("expanded chat fuzz payload exceeds the contract byte ceiling")
    return [action.model_copy(update={"message": message})]


def _mutate_api(
    action: InvokeApprovedApiRequestActionV1,
    *,
    operator: FuzzMutationOperatorV2,
    entry: FuzzCorpusEntryV1,
) -> list[AttackActionV1]:
    body = dict(action.body)
    if operator in {
        FuzzMutationOperatorV2.APPEND_FRAGMENT,
        FuzzMutationOperatorV2.PREPEND_FRAGMENT,
        FuzzMutationOperatorV2.REPLACE_VALUE,
    }:
        fragment = _bounded_text(entry.value)
        current = body.get("message", "")
        if not isinstance(current, str):
            raise ValueError("text fuzz operators require a string message field")
        body["message"] = (
            f"{current}{fragment}"
            if operator == FuzzMutationOperatorV2.APPEND_FRAGMENT
            else f"{fragment}{current}"
            if operator == FuzzMutationOperatorV2.PREPEND_FRAGMENT
            else fragment
        )
    elif operator == FuzzMutationOperatorV2.REMOVE_FIELD:
        field_name = _bounded_text(entry.value)
        body.pop(field_name, None)
    elif operator == FuzzMutationOperatorV2.ADD_EXTRA_FIELD:
        field_name = _bounded_text(entry.value)
        body[field_name] = "agentforge-safe-extra-field"
    elif operator == FuzzMutationOperatorV2.CHANGE_JSON_TYPE:
        body["message"] = entry.value
    elif operator == FuzzMutationOperatorV2.CORRELATION_MISMATCH:
        return [action.model_copy(update={"correlation_mode": "mismatch"})]
    else:
        raise ValueError("operator is not supported for an API mutation point")
    return [action.model_copy(update={"body": body})]


def _mutate_sequence(
    plan: FuzzPlanV2,
    *,
    operator: FuzzMutationOperatorV2,
    entry: FuzzCorpusEntryV1,
) -> list[AttackActionV1]:
    actions: list[AttackActionV1] = []
    mutated = False
    for action in plan.base_sequence:
        if action.action_id != plan.mutation_point_action_id:
            actions.append(action)
            continue
        mutated = True
        if isinstance(action, SendChatMessageActionV1):
            actions.extend(_mutate_chat(action, operator=operator, entry=entry))
        elif isinstance(action, InvokeApprovedApiRequestActionV1):
            actions.extend(_mutate_api(action, operator=operator, entry=entry))
        else:
            raise ValueError("fuzz mutation point must be a chat or approved API action")
    if not mutated:
        raise ValueError("fuzz mutation point was not found")
    if len(actions) > 30:
        raise ValueError("expanded fuzz sequence exceeds the action ceiling")
    return actions


def expand_fuzz_plan(
    proposal: ProposedAttackV1,
    corpus: FuzzCorpusV1,
) -> list[ExpandedFuzzVariantV2]:
    """Expand at most six exact variants using only versioned corpus/operator pairs."""

    plan = proposal.fuzz_plan
    if plan is None:
        raise ValueError("fuzz expansion requires a proposal with FuzzPlanV2")
    entries = {entry.corpus_id: entry for entry in corpus.entries}
    candidates: list[tuple[FuzzMutationOperatorV2, FuzzCorpusEntryV1]] = []
    for operator in plan.operator_ids:
        for corpus_id in plan.corpus_ids:
            entry = entries.get(corpus_id)
            if entry is None:
                raise ValueError(f"unknown fuzz corpus ID: {corpus_id}")
            if operator in entry.operators:
                candidates.append((operator, entry))
    if not candidates:
        raise ValueError("fuzz plan has no compatible operator/corpus pair")
    random.Random(plan.rng_seed).shuffle(candidates)  # noqa: S311 - reproducible fuzz ordering

    variants: list[ExpandedFuzzVariantV2] = []
    seen_hashes: set[str] = set()
    for operator, entry in candidates:
        actions = _mutate_sequence(plan, operator=operator, entry=entry)
        action_payload = [action.model_dump(mode="json") for action in actions]
        payload_hash = _hash(action_payload)
        if payload_hash in seen_hashes:
            continue
        seen_hashes.add(payload_hash)
        index = len(variants)
        variant_mutation_point = (
            f"{plan.mutation_point_action_id}-a"
            if operator == FuzzMutationOperatorV2.SPLIT_MULTI_TURN
            else plan.mutation_point_action_id
        )
        variant_plan = FuzzPlanV2.model_validate_json(
            json.dumps(
                {
                    **plan.model_dump(mode="json"),
                    "base_sequence": action_payload,
                    "mutation_point_action_id": variant_mutation_point,
                }
            )
        )
        variant_proposal = ProposedAttackV1.model_validate_json(
            json.dumps(
                {
                    **proposal.model_dump(mode="json"),
                    "proposal_id": f"{proposal.proposal_id}-fz{index}",
                    "attack_family_id": f"{proposal.attack_family_id}-fz{index}",
                    "ordered_actions": action_payload,
                    "fuzz_plan": variant_plan.model_dump(mode="json"),
                }
            )
        )
        variants.append(
            ExpandedFuzzVariantV2(
                variant_id=f"fuzz-{payload_hash[:16]}",
                variant_index=index,
                operator_id=operator,
                corpus_id=entry.corpus_id,
                rng_seed=plan.rng_seed,
                exact_payload_hash=payload_hash,
                proposal=variant_proposal,
            )
        )
        if len(variants) >= plan.max_variants:
            break
    return variants


def _canonical_action_bytes(actions: list[AttackActionV1]) -> bytes:
    return json.dumps(
        [action.model_dump(mode="json") for action in actions],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _shorter_texts(value: str) -> list[str]:
    if len(value) <= 1:
        return []
    pivot = max(1, len(value) // 2)
    candidates = [value[pivot:], value[:pivot]]
    edge = max(1, len(value) // 4)
    candidates.append(f"{value[:edge]}{value[-edge:]}")
    return list(dict.fromkeys(item for item in candidates if 0 < len(item) < len(value)))


def _with_suffix(value: str, suffix: str, *, maximum: int = 100) -> str:
    return f"{value[: maximum - len(suffix)]}{suffix}"


def _minimized_sequences(proposal: ProposedAttackV1) -> list[list[AttackActionV1]]:
    candidates: list[list[AttackActionV1]] = []
    actions = list(proposal.ordered_actions)
    mutable_indexes = [
        index
        for index, action in enumerate(actions)
        if isinstance(action, (SendChatMessageActionV1, InvokeApprovedApiRequestActionV1))
    ]
    for index in mutable_indexes:
        action = actions[index]
        if isinstance(action, SendChatMessageActionV1):
            for message in _shorter_texts(action.message):
                candidate = list(actions)
                candidate[index] = action.model_copy(update={"message": message})
                candidates.append(candidate)
        else:
            message = action.body.get("message")
            if isinstance(message, str):
                for shorter in _shorter_texts(message):
                    candidate = list(actions)
                    body = dict(action.body)
                    body["message"] = shorter
                    candidate[index] = action.model_copy(update={"body": body})
                    candidates.append(candidate)
            optional_fields = sorted(
                key for key in action.body if key not in {"message", "patient_id", "user_id"}
            )
            for field_name in optional_fields:
                candidate = list(actions)
                body = dict(action.body)
                body.pop(field_name)
                candidate[index] = action.model_copy(update={"body": body})
                candidates.append(candidate)
    if len(mutable_indexes) > 1:
        for index in mutable_indexes:
            if index + 1 >= len(actions) or not isinstance(
                actions[index + 1], WaitForResponseActionV1
            ):
                continue
            candidate = actions[:index] + actions[index + 2 :]
            if any(
                isinstance(
                    item,
                    (SendChatMessageActionV1, InvokeApprovedApiRequestActionV1),
                )
                for item in candidate
            ):
                candidates.append(candidate)
    return candidates


def minimize_confirmed_fuzz_variant(
    proposal: ProposedAttackV1,
    *,
    parent_attempt_id: str,
    maximum_candidates: int = 3,
) -> list[MinimizedFuzzCandidateV2]:
    """Create up to three deterministic smaller replays for a confirmed fuzz variant."""

    if proposal.fuzz_plan is None or proposal.technique.value != "fuzzing":
        raise ValueError("only an expanded fuzz proposal can be minimized")
    if not 1 <= maximum_candidates <= 3:
        raise ValueError("fuzz minimization permits between one and three candidates")
    original_bytes = _canonical_action_bytes(proposal.ordered_actions)
    original_hash = hashlib.sha256(original_bytes).hexdigest()
    seen: set[str] = set()
    minimized: list[MinimizedFuzzCandidateV2] = []
    for actions in _minimized_sequences(proposal):
        payload = _canonical_action_bytes(actions)
        if len(payload) >= len(original_bytes):
            continue
        payload_hash = hashlib.sha256(payload).hexdigest()
        if payload_hash in seen:
            continue
        seen.add(payload_hash)
        mutation_points = [
            action.action_id
            for action in actions
            if isinstance(action, (SendChatMessageActionV1, InvokeApprovedApiRequestActionV1))
        ]
        if not mutation_points:
            continue
        index = len(minimized)
        plan = FuzzPlanV2.model_validate_json(
            json.dumps(
                {
                    **proposal.fuzz_plan.model_dump(mode="json"),
                    "base_sequence": [action.model_dump(mode="json") for action in actions],
                    "mutation_point_action_id": (
                        proposal.fuzz_plan.mutation_point_action_id
                        if proposal.fuzz_plan.mutation_point_action_id in mutation_points
                        else mutation_points[0]
                    ),
                }
            )
        )
        candidate = ProposedAttackV1.model_validate_json(
            json.dumps(
                {
                    **proposal.model_dump(mode="json"),
                    "proposal_id": _with_suffix(proposal.proposal_id, f"-min{index}"),
                    "attack_family_id": _with_suffix(proposal.attack_family_id, f"-min{index}"),
                    "parent_attempt_id": parent_attempt_id,
                    "ordered_actions": [action.model_dump(mode="json") for action in actions],
                    "fuzz_plan": plan.model_dump(mode="json"),
                }
            )
        )
        minimized.append(
            MinimizedFuzzCandidateV2(
                candidate_id=f"min-{payload_hash[:16]}",
                candidate_index=index,
                parent_payload_hash=original_hash,
                exact_payload_hash=payload_hash,
                original_payload_bytes=len(original_bytes),
                candidate_payload_bytes=len(payload),
                proposal=candidate,
            )
        )
        if len(minimized) >= maximum_candidates:
            break
    return minimized


__all__ = [
    "ExpandedFuzzVariantV2",
    "FuzzCorpusEntryV1",
    "FuzzCorpusV1",
    "MinimizedFuzzCandidateV2",
    "expand_fuzz_plan",
    "load_fuzz_corpus",
    "minimize_confirmed_fuzz_variant",
]
