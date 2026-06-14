

    # Walk chain to verify scope transitions
    prev_scope = None
    for entry in envelope.delegation:
        # Verify evidence hash
        entry_bytes = json.dumps(asdict(entry), separators=(",", ":"), sort_keys=True).encode()
        computed_hash = hashlib.sha256(entry_bytes).hexdigest()
        if computed_hash != entry.evidence_hash:
            return False, f"Delegation entry hash mismatch for {entry.delegate_did}"
        
        # Verify ordering: later delegations must have later timestamps
        if prev_scope is not None:
            if entry.delegated_at < prev_scope:
                return False, f"Delegation timestamp ordering violation"
        prev_scope = entry.delegated_at
    
    # Verify envelope is signed by current delegate (end of chain)
    current_delegate = envelope.delegation[0].delegate_did if envelope.delegation else envelope.subject
    if envelope.issuer != current_delegate:
        return False, f"Envelope issuer {envelope.issuer} != current delegate {current_delegate}"
    
    # Verify log anchor if present
    if envelope.log_entry_hash and envelope.log_url:
        try:
            import requests
            r = requests.get(
                f"{envelope.log_url}/proof/{envelope.log_entry_hash}",
                timeout=5,
            )
            if r.status_code != 200:
                return False, f"CT log anchor not verifiable at {envelope.log_url}"
        except Exception as e:\n            return False, f"CT log lookup failed: {e}"
    
    return True, f"Valid delegation chain with {len(envelope.delegation)} hop(s)"


def build_aip_envelope_for_pact_agent(
    agent_did: str,
    operator_did: str,
    agent_claims: Dict[str, Any],
    signing_key: bytes,
    log_url: Optional[str] = None,
    expires_at: Optional[str] = None,
) -> Tuple[AIPEnvelope, Optional[str]]:
    """
    Build and sign an AIP Registration Envelope for a PACT agent.
    
    This is what PACT agents use as their identity layer — instead of a CA cert,
    they have an AIP envelope anchored to a transparency log.
    
    Args:
        agent_did: The agent's AIP DID (did:aip:...)
        operator_did: The operator's DID (did:key or did:aip)
        agent_claims: What this envelope asserts about the agent
            - name, mission, allowed_tools, policy_hash, etc.
        signing_key: Ed25519 private key bytes for signing the envelope
        log_url: Optional CT log to anchor the envelope in
        expires_at: Optional expiration (ISO 8601)
    
    Returns:
        (AIPEnvelope, log_entry_hash) — log_entry_hash is None if no log anchor
    """
    import requests
    
    envelope = AIPEnvelope(
        issuer=operator_did,
        subject=agent_did,
        claims=agent_claims,
        delegation=[],
        issued_at=datetime.now(timezone.utc).isoformat(),
        expires_at=expires_at,
        sequence=0,
    )
    
    # Anchor to CT log if URL provided
    log_entry_hash = None
    log_index = None
    if log_url:
        try:
            # Sign the envelope first
            sig = envelope.sign(signing_key)
            envelope_dict = asdict(envelope)
            envelope_dict["signature"] = sig
            
            # Submit to CT log
            r = requests.post(
                f"{log_url}/envelopes",
                json=envelope_dict,
                timeout=10,
            )
            if r.status_code in (200, 201):
                result = r.json()
                log_entry_hash = result.get("logEntryHash")
                log_index = result.get("logIndex")
                envelope.log_entry_hash = log_entry_hash
                envelope.log_index = log_index
                envelope.log_url = log_url
        except Exception as e:\n            # Non-fatal: log anchor is optional
            pass
    
    return envelope, log_entry_hash


# ---------------------------------------------------------------------------
# PACT Receipt ← AIP Integration
# ---------------------------------------------------------------------------

@dataclass
class PACTReceiptWithAIP:
    """
    PACT receipt with AIP DID identity layer.
    
    Extends the base PACT receipt with:
      - issuer_did: AIP DID of the entity that signed the receipt
      - issuer_doc: Full AIP DID Document for the issuer
      - envelope: The AIP Registration Envelope for this identity
      - delegation_proof: Optional proof of delegation chain (for non-self-signed)
    """
    # Base PACT fields (from PACTReceipt)
    action_id: str
    agent_id: str
    tool_called: str
    policy_hash: str
    timestamp: str
    
    # AIP identity fields
    issuer_did: str
    issuer_doc: Optional[AIPDIDDocument] = None
    envelope: Optional[AIPEnvelope] = None
    delegation_proof: Optional[List[AIPDelegationEntry]] = None
    
    # Signature over receipt commitment
    signature: Optional[str] = None
    verifier_key: Optional[str] = None  # base64 encoded issuer verification key
    
    def to_dict(self) -> Dict:
        result = {
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "tool_called": self.tool_called,
            "policy_hash": self.policy_hash,
            "timestamp": self.timestamp,
            "issuer_did": self.issuer_did,
        }
        if self.issuer_doc:
            result["issuer_doc"] = self.issuer_doc.to_dict()
        if self.envelope:
            result["envelope"] = asdict(self.envelope)
        if self.delegation_proof:
            result["delegation_proof"] = [asdict(d) for d in self.delegation_proof]
        if self.signature:
            result["signature"] = self.signature
        if self.verifier_key:
            result["verifier_key"] = self.verifier_key
        return result
    
    @classmethod
    def from_base_receipt(cls, receipt: Dict, aip_did: str, issuer_doc: Optional[AIPDIDDocument] = None) -> "PACTReceiptWithAIP":
        """Upgrade a base PACT receipt with AIP identity."""
        return cls(
            action_id=receipt.get("action_id", ""),
            agent_id=receipt.get("agent_id", ""),
            tool_called=receipt.get("tool_called", ""),
            policy_hash=receipt.get("policy_hash", ""),
            timestamp=receipt.get("timestamp", ""),
            issuer_did=aip_did,
            issuer_doc=issuer_doc,
        )


def sign_pact_receipt_with_aip(
    receipt: Dict,
    signing_key: bytes,
    aip_did: str,
    issuer_doc: Optional[AIPDIDDocument] = None,
) -> PACTReceiptWithAIP:
    """
    Sign a PACT receipt using an AIP DID identity.
    
    The signature is over the receipt commitment:
        sha256(policy_hash:tool:action_id:timestamp)
    
    This mirrors how AIP envelopes are signed, but for receipt commitments.
    The AIP DID Document used for verification is included in the receipt,
    allowing third parties to verify the signature without a central authority.
    """
    # Build the commitment (same as PACTReceipt)
    commitment_input = f"{receipt['policy_hash']}:{receipt['tool_called']}:{receipt['action_id']}:{receipt['timestamp']}"
    commitment = hashlib.sha256(commitment_input.encode()).digest()
    
    # Sign with Ed25519
    if not HAS_CRYPTO:
        raise ImportError("cryptography required for signing")
    
    key = ed25519.Ed25519PrivateKey.from_private_bytes(signing_key[:32])
    sig = key.sign(commitment)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    
    # Get verification key for inclusion in receipt
    pubkey_bytes = key.public_key().public_bytes(
        serialization.Encoding.raw,
        serialization.PublicFormat.Raw,
    )
    verifier_key_b64 = base64.urlsafe_b64encode(pubkey_bytes).rstrip(b'=').decode()
    
    receipt_with_aip = PACTReceiptWithAIP.from_base_receipt(receipt, aip_did, issuer_doc)
    receipt_with_aip.signature = sig_b64
    receipt_with_aip.verifier_key = verifier_key_b64
    
    return receipt_with_aip


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="PACT AIP DID Adapter")
    sub = parser.add_subparsers(dest="cmd")
    
    resolve_p = sub.add_parser("resolve")
    resolve_p.add_argument("did", help="did:aip DID to resolve")
    
    envelope_p = sub.add_parser("envelope")
    envelope_p.add_argument("--agent-did", required=True)
    envelope_p.add_argument("--operator-did", required=True)
    envelope_p.add_argument("--claims", default="{}", help="JSON claims object")
    envelope_p.add_argument("--signing-key", required=True, help="Hex-encoded Ed25519 private key")
    envelope_p.add_argument("--log-url", help="CT log URL to anchor envelope")
    envelope_p.add_argument("--expires-at", help="Expiration ISO 8601")
    
    sign_p = sub.add_parser("sign-receipt")
    sign_p.add_argument("--receipt", required=True, help="Path to base PACT receipt JSON")
    sign_p.add_argument("--signing-key", required=True, help="Hex-encoded Ed25519 private key")
    sign_p.add_argument("--aip-did", required=True, help="did:aip DID for signing")
    
    args = parser.parse_args()
    
    if args.cmd == "resolve":
        result = resolve_aip_did(args.did)
        if result.resolution_success:
            print(json.dumps(result.document.to_dict(), indent=2))
        else:
            print(f"Resolution failed: {result.error}", file=sys.stderr)
            sys.exit(1)
    
    elif args.cmd == "envelope":
        import base64
        claims = json.loads(args.claims)
        signing_key = bytes.fromhex(args.signing_key)
        expires = args.expires_at
        
        envelope, log_hash = build_aip_envelope_for_pact_agent(
            agent_did=args.agent_did,
            operator_did=args.operator_did,
            agent_claims=claims,
            signing_key=signing_key,
            log_url=args.log_url,
            expires_at=expires,
        )
        
        sig = envelope.sign(signing_key)
        result = asdict(envelope)
        result["signature"] = sig
        
        print(json.dumps(result, indent=2))
        if log_hash:
            print(f"\n[anchored] log entry hash: {log_hash}", file=sys.stderr)
    
    elif args.cmd == "sign-receipt":
        import base64
        with open(args.receipt) as f:\n            receipt = json.load(f)\n        \n        signing_key = bytes.fromhex(args.signing_key)\n        result = sign_pact_receipt_with_aip(receipt, signing_key, args.aip_did)
        print(json.dumps(result.to_dict(), indent=2))
    
    else:
        parser.print_help()
