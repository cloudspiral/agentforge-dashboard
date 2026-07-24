from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentforge.contracts.v1 import (
    FuzzMutationOperatorV2,
    FuzzPlanV2,
    ProposedAttackV1,
)
from agentforge.evaluation import (
    expand_fuzz_plan,
    load_fuzz_corpus,
    load_seed_case,
    load_taxonomy,
    minimize_confirmed_fuzz_variant,
)
from agentforge.orchestration.objectives import proposal_from_seed
from agentforge.target import load_target_profile

ROOT = Path(__file__).resolve().parents[2]


def _fuzz_proposal() -> ProposedAttackV1:
    case = load_seed_case(ROOT / "evals" / "seed-cases" / "pi-direct-instruction-override.yaml")
    taxonomy = load_taxonomy(ROOT / "config" / "attack-taxonomy.yaml")
    profile = load_target_profile(ROOT / "config" / "target-profile.yaml")
    base = proposal_from_seed(
        case,
        campaign_id="unit-fuzz-campaign",
        taxonomy=taxonomy,
        profile=profile.profile,
    )
    operation = next(
        action for action in base.ordered_actions if action.action_type == "send_chat_message"
    )
    plan = {
        "schema_version": "v2",
        "mutation_point_action_id": operation.action_id,
        "operator_ids": [FuzzMutationOperatorV2.APPEND_FRAGMENT],
        "corpus_ids": ["text.long_bounded"],
        "rng_seed": 17,
        "max_variants": 1,
    }
    return ProposedAttackV1.model_validate_json(
        json.dumps(
            {
                **base.model_dump(mode="json"),
                "technique": "fuzzing",
                "fuzz_plan": plan,
            }
        )
    )


def test_fuzz_proposal_hydrates_one_authoritative_base_sequence() -> None:
    proposal = _fuzz_proposal()

    assert proposal.fuzz_plan is not None
    assert proposal.fuzz_plan.base_sequence == proposal.ordered_actions
    assert len(proposal.fuzz_plan.base_sequence) >= 5


def test_standalone_fuzz_plan_still_requires_a_replayable_base_sequence() -> None:
    with pytest.raises(ValueError, match="at least 5"):
        FuzzPlanV2(
            mutation_point_action_id="a3",
            operator_ids=[FuzzMutationOperatorV2.APPEND_FRAGMENT],
            corpus_ids=["text.long_bounded"],
            rng_seed=17,
            max_variants=1,
        )


def test_fuzz_proposal_rejects_an_explicit_mismatched_base_sequence() -> None:
    proposal = _fuzz_proposal()
    payload = proposal.model_dump(mode="json")
    assert isinstance(payload["fuzz_plan"], dict)
    payload["fuzz_plan"]["base_sequence"] = payload["ordered_actions"][:-1]

    with pytest.raises(ValueError, match="base_sequence must equal ordered_actions"):
        ProposedAttackV1.model_validate_json(json.dumps(payload))


def test_fuzz_expansion_and_confirmed_variant_minimization_are_reproducible() -> None:
    corpus = load_fuzz_corpus(ROOT / "config" / "fuzz-corpus.yaml")
    expanded = expand_fuzz_plan(_fuzz_proposal(), corpus)
    assert len(expanded) == 1

    candidates = minimize_confirmed_fuzz_variant(
        expanded[0].proposal,
        parent_attempt_id="00000000-0000-4000-8000-000000000001",
    )
    repeated = minimize_confirmed_fuzz_variant(
        expanded[0].proposal,
        parent_attempt_id="00000000-0000-4000-8000-000000000001",
    )

    assert 1 <= len(candidates) <= 3
    assert [item.model_dump(mode="json") for item in candidates] == [
        item.model_dump(mode="json") for item in repeated
    ]
    assert len({item.exact_payload_hash for item in candidates}) == len(candidates)
    assert all(item.candidate_payload_bytes < item.original_payload_bytes for item in candidates)
    assert all(
        item.proposal.parent_attempt_id == "00000000-0000-4000-8000-000000000001"
        for item in candidates
    )
    assert all(
        item.proposal.fuzz_plan is not None
        and item.proposal.fuzz_plan.base_sequence == item.proposal.ordered_actions
        for item in candidates
    )


def test_minimization_rejects_non_fuzz_proposals() -> None:
    scenario = proposal_from_seed(
        load_seed_case(ROOT / "evals" / "seed-cases" / "pi-direct-instruction-override.yaml"),
        campaign_id="unit-scenario-campaign",
        taxonomy=load_taxonomy(ROOT / "config" / "attack-taxonomy.yaml"),
        profile=load_target_profile(ROOT / "config" / "target-profile.yaml").profile,
    )
    with pytest.raises(ValueError, match="expanded fuzz"):
        minimize_confirmed_fuzz_variant(
            scenario,
            parent_attempt_id="00000000-0000-4000-8000-000000000001",
        )
