"""AI routes.

These endpoints are advisory only. They never influence the release gate, never
apply a patch without an explicit, confirmed approval call, and never return the
provider API key. When no provider is configured they answer with
``configured = false`` and an actionable message instead of inventing content.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from ..schemas import (
    AIChatRequest,
    AIChatResponse,
    AIConversationOut,
    AIReviewOut,
    AIReviewRequest,
    ApproveRequest,
    ConversationOut,
    GenericMessage,
    RemediationOut,
    RemediationProposeRequest,
    SummaryOut,
    SummaryRequest,
    TestGenerateOut,
    ThreatModelOut,
    ThreatModelRequest,
)
from ..intelligence.contracts import IntelligenceRequest, Operation
from .deps import Services, get_services, require_admin, require_analyst

router = APIRouter(tags=["ai"])

ServicesDep = Annotated[Services, Depends(get_services)]
AnalystDep = Annotated[dict, Depends(require_analyst)]
AdminDep = Annotated[dict, Depends(require_admin)]


# ------------------------------------------------------------------- assistant
@router.post("/api/ai/chat", response_model=AIChatResponse)
def chat(payload: AIChatRequest, services: ServicesDep, user: AnalystDep) -> dict:
    result = services.intelligence.execute(IntelligenceRequest(
        operation=Operation.ASSISTANT_CHAT, question=payload.message,
        repository_id=payload.repository_id, conversation_id=payload.conversation_id,
    ), user=user)
    data = result.data
    conversation_id = data.get("conversation_id")
    message = services.store.list_messages(conversation_id)[-1] if conversation_id else {
        "id": 0, "role": "assistant", "content": result.summary, "created_at": "", "metadata": {}
    }
    return {"conversation_id": conversation_id or 0, "message": message,
            "configured": bool(result.provider),
            "sources": [item.model_dump() for item in result.evidence],
            "task_id": result.task_id, "confidence": result.confidence.value,
            "limitations": result.limitations, "status": result.status.value,
            "execution": result.execution_kind.value, "provider": result.provider, "model": result.model,
            "latency_ms": result.latency_ms, "fallback_used": result.fallback_used}


@router.get("/api/ai/conversations", response_model=list[ConversationOut])
def list_conversations(services: ServicesDep, repository_id: int | None = None) -> list[dict]:
    conversations = services.store.list_conversations(repository_id)
    return [
        {**item, "message_count": len(services.store.list_messages(item["id"]))}
        for item in conversations
    ]


@router.get("/api/ai/conversations/{conversation_id}", response_model=AIConversationOut)
def get_conversation(conversation_id: int, services: ServicesDep) -> dict:
    conversation = services.store.get_conversation(conversation_id)
    if conversation is None:
        raise KeyError(f"Conversation {conversation_id} was not found.")
    return conversation


@router.delete("/api/ai/conversations/{conversation_id}", response_model=GenericMessage)
def delete_conversation(conversation_id: int, services: ServicesDep, _user: AnalystDep) -> dict:
    if services.store.get_conversation(conversation_id) is None:
        raise KeyError(f"Conversation {conversation_id} was not found.")
    services.store.delete_conversation(conversation_id)
    return {"detail": "Conversation deleted."}


# -------------------------------------------------------------- security analyst
@router.post("/api/ai/findings/{finding_id}/review", response_model=AIReviewOut)
def review_finding(
    finding_id: int, payload: AIReviewRequest, services: ServicesDep, user: AnalystDep
) -> dict:
    result = services.intelligence.execute(IntelligenceRequest(
        operation=Operation.DIAGNOSE_FAILURE, finding_id=finding_id, scope=payload.kind,
    ), user=user)
    content = {
        "kind": payload.kind, "text": result.data.get("probable_root_cause") or result.summary
    }
    return {"finding_id": finding_id,
            "configured": bool(result.provider),
            "provider": result.provider, "model": result.model,
            "error": None, "content": content,
            "task_id": result.task_id, "confidence": result.confidence.value,
            "evidence": [item.model_dump() for item in result.evidence],
            "limitations": result.limitations, "status": result.status.value,
            "execution": result.execution_kind.value, "latency_ms": result.latency_ms}


@router.post("/api/ai/findings/{finding_id}/test", response_model=TestGenerateOut)
def generate_test(finding_id: int, services: ServicesDep, _user: AnalystDep) -> dict:
    """Draft a regression test. It is returned as text and never written to disk."""
    return services.ai.generate_test(finding_id)


# ----------------------------------------------------------------- remediation
@router.post("/api/ai/remediations", response_model=RemediationOut, status_code=201)
def propose_remediation(
    payload: RemediationProposeRequest, services: ServicesDep, _user: AnalystDep
) -> dict:
    """Generate a patch proposal. Nothing is applied to the working tree."""
    return services.ai.propose_remediation(payload.finding_id)


@router.get("/api/ai/remediations", response_model=list[RemediationOut])
def list_remediations(
    services: ServicesDep,
    repository_id: int | None = None,
    finding_id: int | None = None,
) -> list[dict]:
    return services.store.list_proposals(repository_id=repository_id, finding_id=finding_id)


@router.get("/api/ai/remediations/{proposal_id}", response_model=RemediationOut)
def get_remediation(proposal_id: int, services: ServicesDep) -> dict:
    proposal = services.store.get_proposal(proposal_id)
    if proposal is None:
        raise KeyError(f"Proposal {proposal_id} was not found.")
    return proposal


@router.post("/api/ai/remediations/{proposal_id}/approve", response_model=RemediationOut)
def approve_remediation(
    proposal_id: int, payload: ApproveRequest, services: ServicesDep, user: AdminDep
) -> dict:
    """Apply a proposal to the working tree.

    Requires ``confirm = true``; a backup of the original file is written first
    so the change can be rolled back.
    """
    return services.intelligence.tools.call(
        "approve_remediation",
        {"proposal_id": proposal_id, "confirm": payload.confirm,
         "run_tests": payload.run_tests, "explicit_permission": payload.explicit_permission},
        user=user,
    )["result"]


@router.post("/api/ai/remediations/{proposal_id}/rollback", response_model=RemediationOut)
def rollback_remediation(proposal_id: int, services: ServicesDep, _user: AdminDep) -> dict:
    return services.ai.rollback_remediation(proposal_id)


# ---------------------------------------------------------------------- reports
@router.post("/api/ai/summary", response_model=SummaryOut)
def executive_summary(payload: SummaryRequest, services: ServicesDep, _user: AnalystDep) -> dict:
    return services.ai.executive_summary(
        repository_id=payload.repository_id, scan_id=payload.scan_id
    )


@router.post("/api/ai/threat-model", response_model=ThreatModelOut)
def threat_model(payload: ThreatModelRequest, services: ServicesDep, _user: AnalystDep) -> dict:
    return services.ai.threat_model(payload.repository_id)
