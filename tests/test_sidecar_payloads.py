from trustchain.sidecar import TrustChainSidecar


def test_receive_proposal_wraps_payload(monkeypatch):
    sidecar = TrustChainSidecar(name="payload-test", auto_start=False)
    seen: dict[str, object] = {}

    def fake_post(path: str, body=None):
        seen["path"] = path
        seen["body"] = body
        return {"accepted": True}

    monkeypatch.setattr(sidecar, "_post", fake_post)

    proposal = {"public_key": "a" * 64, "sequence_number": 1}
    result = sidecar.receive_proposal(proposal)

    assert result == {"accepted": True}
    assert seen["path"] == "/receive_proposal"
    assert seen["body"] == {"proposal": proposal}


def test_receive_agreement_wraps_payload(monkeypatch):
    sidecar = TrustChainSidecar(name="payload-test", auto_start=False)
    seen: dict[str, object] = {}

    def fake_post(path: str, body=None):
        seen["path"] = path
        seen["body"] = body
        return {"accepted": True}

    monkeypatch.setattr(sidecar, "_post", fake_post)

    agreement = {"public_key": "b" * 64, "sequence_number": 2}
    result = sidecar.receive_agreement(agreement)

    assert result == {"accepted": True}
    assert seen["path"] == "/receive_agreement"
    assert seen["body"] == {"agreement": agreement}
