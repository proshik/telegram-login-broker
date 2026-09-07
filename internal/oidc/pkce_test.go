package oidc

import "testing"

// RFC 7636 Appendix B.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestS256ChallengeMatchesRFC7636Vector(t *testing.T) {
	if got := S256Challenge(rfcVerifier); got != rfcChallenge {
		t.Errorf("S256Challenge() = %q, want %q", got, rfcChallenge)
	}
}

func TestVerifyPKCEAcceptsMatchingVerifier(t *testing.T) {
	if err := VerifyPKCE(rfcChallenge, rfcVerifier); err != nil {
		t.Errorf("VerifyPKCE() = %v, want nil", err)
	}
}

func TestVerifyPKCERejectsWrongVerifier(t *testing.T) {
	if err := VerifyPKCE(rfcChallenge, "not-the-verifier-that-produced-that-challenge"); err == nil {
		t.Error("VerifyPKCE() = nil for a wrong verifier, want error")
	}
}

func TestVerifyPKCERejectsPlainVerifierEqualToChallenge(t *testing.T) {
	// The "plain" method is not offered. A client that sends the verifier as its
	// own challenge must not be silently downgraded into it.
	if err := VerifyPKCE(rfcVerifier, rfcVerifier); err == nil {
		t.Error("VerifyPKCE() accepted plain-method equality, want error")
	}
}

func TestValidateChallengeFormat(t *testing.T) {
	if err := ValidateChallengeFormat(rfcChallenge); err != nil {
		t.Errorf("ValidateChallengeFormat(valid) = %v, want nil", err)
	}

	bad := map[string]string{
		"empty":       "",
		"too short":   "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c",
		"too long":    rfcChallenge + "A",
		"padded":      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=",
		"std base64":  "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM",
		"with slash":  "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw/cM",
		"non-ascii":   "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cЖ",
		"whitespace":  "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw c",
		"punctuation": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw.cM",
	}
	for name, challenge := range bad {
		if err := ValidateChallengeFormat(challenge); err == nil {
			t.Errorf("ValidateChallengeFormat(%s) = nil, want error", name)
		}
	}
}
