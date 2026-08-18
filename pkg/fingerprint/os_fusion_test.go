package fingerprint_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestGenericOpenSSHNotConfidentLinux(t *testing.T) {
	claims := []model.Claim{{
		Kind: model.ClaimOS, Family: "linux", Product: "Linux", Score: 90,
		CorrelationGroup: "ssh_banner", RuleIDs: []string{"openssh-banner"},
	}}
	out := fingerprint.FuseOS(claims)
	if len(out) != 1 {
		t.Fatalf("%+v", out)
	}
	if out[0].Confidence == model.ConfidenceExact || out[0].Confidence == model.ConfidenceStrong {
		t.Fatalf("generic OpenSSH must not be strong/exact Linux: %+v", out[0])
	}
}

func TestSMBWindowsRemainsStrong(t *testing.T) {
	claims := []model.Claim{{
		Kind: model.ClaimOS, Family: "windows", Product: "Windows", Score: 92,
		CorrelationGroup: "smb_ntlm", RuleIDs: []string{"smb-ntlm-windows"},
	}}
	out := fingerprint.FuseOS(claims)
	if out[0].Confidence != model.ConfidenceStrong && out[0].Confidence != model.ConfidenceExact {
		t.Fatalf("SMB windows should stay strong: %+v", out[0])
	}
}
