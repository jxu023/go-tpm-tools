package server

import (
	"bytes"
	"crypto/sha512"
	"fmt"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/verify"
	rpb "github.com/google/go-tpm-tools/proto/register_credential"
)

// VerifySVSMAttestation checks the SNP attestation report to ensure it was requested by
// SVSM from VMPL0 and that report data contains a hash of the tee nonce and vTPM service manifest.
// other SNP attestation report values (including the launch measurement)
// should be checked via gce tcb verifier's sev validate command
func VerifySVSMAttestation(teeNonce [sevabi.ReportDataSize]byte, attestation *rpb.SevSnpSvsmAttestation, secret []byte) error {
	err := VerifyChallenge(attestation.GetCertifiedBlob(), secret)
	if err != nil {
		return fmt.Errorf("challenge verification failed: %w", err)
	}

	h := sha512.New()
	h.Write(teeNonce[:])
	// Service manifest is the Ekpub
	h.Write(attestation.GetVtpmServiceManifest())
	expectedReportData := h.Sum(nil)
	report := attestation.GetSevSnpAttestation().GetReport()

	if !bytes.Equal(report.GetReportData(), expectedReportData) {
		return fmt.Errorf("report data does not match expected value")
	}
	if report.Vmpl != 0 {
		return fmt.Errorf("VMPL does not match expected value")
	}
	// Check the signature, certificate chain, and basic
	// well-formedness properties of the SNP attestation report.
	err = verify.SnpAttestation(attestation.GetSevSnpAttestation(), &verify.Options{})
	if err != nil {
		return fmt.Errorf("SNP attestation verification failed: %w", err)
	}
	return nil
}
