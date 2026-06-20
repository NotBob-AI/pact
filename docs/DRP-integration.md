# PACT × DRP Integration — Delegation Receipt Protocol (IETF draft-nelson)

> **Status**: Research + Draft Architecture  
> **Source**: draft-nelson-agent-delegation-receipts-09 (IETF, May 2026, expires Nov 2026)  
> **PACT milestone**: Post-v0.8 planning

---

## What DRP Is

The Delegation Receipt Protocol (DRP) fills the **upstream** user-to-operator trust gap that existing IETF frameworks (WIMSE, AIP, OAuth 2.0 Token Exchange) do not address.

DRP's core primitive: before any agent action executes, the **authorizing user** signs an Authorization Object containing scope boundaries, time window, operator instruction hash, and **model state commitment**. This signed receipt is published to an append-only log **before** the agent runtime receives control.

This is architecturally complementary to PACT — DRP is the user's receipt; PACT is the operator's receipt. Together they form a complete user→operator→agent accountability chain.

---

## DRP's Three Novel Contributions

### 1. Model State Attestation

The delegation receipt is bound to a cryptographic **measurement of the model state** at authorization time. If the operator substitutes a different model after the user signs the receipt, the measurement changes and execution is blocked.

This closes the **operator model substitution attack**: the operator claims the user authorized GPT-4o but actually runs a cheaper/faster model. DRP detects this because the model state hash at execution must match the committed hash.

**PACT integration**: PACT's Layer 0 interceptor can incorporate a `model_state_hash` field into the receipt envelope. The interceptor reads the model identity (from the agent's environment or MCP initialization params) and includes it in the receipt Merkle leaf. DRP compliance = PACT receipt includes model state hash matching the DRP Authorization Object.

### 2. Scope Discovery Protocol

Before authorization, the agent runs in a **sandboxed observation mode** with no real resource access. It simulates the intended task and records every resource it attempts to access. This produces a draft `ScopeSchema` grounded in actual agent behavior — not operator-specified assumptions.

The user reviews a plain-language summary and signs only what they explicitly approve.

**PACT integration**: PACT's policy commitment layer already has `allowedTools` and `scopeConstraints`. The Scope Discovery Protocol would generate the initial policy document that PACT then commits to the log. PACT's policy format can serve as the output of the Scope Discovery Protocol, bridging the "what did the agent actually try to do?" gap with "what was the user told the agent could do?"

### 3. Session State + Adaptive Authorization

A continuously updated **trust score** tracks behavioral anomalies across the session lifetime. Trust decays on anomaly detection and recovers slowly on clean behavior. Decision thresholds tighten automatically as trust degrades. Sessions suspend when trust falls below a configurable floor.

**PACT integration**: PACT's revocation model (runtime passport state on every call) is a binary version of this. The DRP adaptive model extends it to a continuous score. PACT's `passport.revoked` flag could be enhanced with a `trust_score` float that gates which policy tiers apply. DRP's adaptive thresholds could be PACT policy rules: `if trust_score < 0.4: restrict_to_read_only_tools`.

---

## Stacking: DRP + PACT = Complete Accountability Chain

```
User → signs DRP Authorization Object → published to append-only log
                                      ↓
Operator → PACT Layer 0 intercepts → checks against user-authorized policy
              → generates PACT receipt → published to same append-only log
                                      ↓
Agent executes → MCP tool call → PACT receipt generated BEFORE forwarding
                                      ↓
Service → Notarized Agents receipt (arxiv 2606.04193) → published to log
```

The append-only log now contains:
1. **DRP receipt**: user authorized this scope, at this model state, for this time window
2. **PACT receipt**: operator verified action against authorized policy, before forwarding
3. **Notarized Agents receipt**: service received exactly this call, observed independently

Neither the user, operator, nor service can unilaterally falsify the chain. The receipts are cryptographically independent.

---

## Concrete PACT Adapter: DRP Authorization Ingestion

PACT should add a `DrpAuthorizationAdapter` that:

1. **Reads DRP Authorization Objects** from the append-only log
2. **Maps DRP scope** → PACT policy document (`allowedTools`, `scopeConstraints`, `time_window`)
3. **Includes model_state_hash** in PACT receipt envelope (for DRP compliance)
4. **Publishes PACT receipts** to the same log DRP uses

```python
class DrpAuthorizationAdapter:
    """
    Bridges DRP (user-to-operator) Authorization Objects into PACT (operator-to-agent) policy enforcement.
    
    Input: DRP Authorization Object from append-only log
    Output: PACT policy document committed to same log, PACT receipts including model_state_hash
    """
    
    def ingest_authorization(self, drp_auth_obj: dict) -> PolicySpec:
        """Parse DRP Authorization Object → PACT PolicySpec."""
        scope = drp_auth_obj["authorization_scope"]
        time_window = drp_auth_obj["validity_window"]
        model_state = drp_auth_obj["model_state_commitment"]
        
        return PolicySpec(
            allowed_tools=scope["permitted_tools"],
            scope_constraints=scope["resource_constraints"],
            time_window=time_window,
            model_state_hash=model_state["hash"],
            drp_receipt_id=drp_auth_obj["receipt_id"],
        )
    
    def generate_pact_receipt_with_model_attestation(
        self, policy: PolicySpec, tool_call: dict, model_state_hash: str
    ) -> Receipt:
        """
        PACT Layer 0 receipt INCLUDING model state attestation.
        The model_state_hash is read from the running environment and
        included in the receipt envelope. DRP verification checks
        receipt.model_state_hash == drp_auth_obj.model_state_commitment.hash.
        """
        assert model_state_hash == policy.model_state_hash, \
            "Model state mismatch — DRP ModelStateAttestation violation"
        return self.receipt_generator.generate(policy, tool_call)
```

---

## What to Ship

1. **`python/pact/drp_adapter.py`** — DrpAuthorizationAdapter class: DRP Auth Obj → PACT PolicySpec, model state attestation
2. **README update** — add DRP to Independent Convergence section with the stacking diagram
3. **Example** — `examples/drp_pact_stacked.js`: full user→operator→agent chain with three receipt types

---

## Relationship to Other PACT Integrations

| Protocol | Layer | PACT Integration |
|---|---|---|
| AIP (did:aip) | Agent identity | PACT DID Adapter resolves AIP identities for receipt signing |
| WIMSE | Service-to-agent trust | PACT Layer 0 verifies WIMSE tokens as input to policy check |
| DRP (this doc) | **User-to-operator trust** | PACT policy document generated from DRP Auth Obj; model state attestation in receipts |
| Notarized Agents | Receiver-side | PACT + Notarized = bilateral chain (already documented) |
| SCITT/COSE_Sign1 | Transparency log | PACT Layer 1 uses SCITT receipts as log entry format (already documented) |
