package server

import (
	"bytes"
	"crypto/sha512"
	"fmt"

	"github.com/google/go-sev-guest/verify"
	rpb "github.com/google/go-tpm-tools/proto/register_credential"
)

type VerifySVSMOpts struct {
	TEENonce    []byte
	Attestation *rpb.SevSnpSvsmAttestation
	Secret      []byte
	VerifyOpts  *verify.Options
}

// VerifySVSMAttestation checks the SNP attestation report to ensure it was requested by
// SVSM from VMPL0 and that report data contains a hash of the tee nonce and vTPM service manifest.
// Other SNP attestation report values (including the launch measurement)
// should be checked via gce tcb verifier's sev validate command.
func VerifySVSMAttestation(opts *VerifySVSMOpts) error {
	err := VerifyCertifiedAKBlob(opts.Attestation.GetCertifiedBlob(), opts.Secret)
	if err != nil {
		return fmt.Errorf("challenge verification failed: %w", err)
	}

	h := sha512.New()
	h.Write(opts.TEENonce[:])
	// Service manifest is the Ekpub.
	h.Write(opts.Attestation.GetVtpmServiceManifest())
	expectedReportData := h.Sum(nil)
	report := opts.Attestation.GetSevSnpAttestation().GetReport()

	if !bytes.Equal(report.GetReportData(), expectedReportData) {
		return fmt.Errorf("report data does not match expected value")
	}
	if report.Vmpl != 0 {
		return fmt.Errorf("attestation report was not requested from VMPL0, SVSM should be in VMPL0")
	}
	// Check the signature, certificate chain, and basic
	// well-formedness properties of the SNP attestation report.
	if opts.VerifyOpts != nil {
		err = verify.SnpAttestation(opts.Attestation.GetSevSnpAttestation(), opts.VerifyOpts)
		if err != nil {
			return fmt.Errorf("SNP attestation verification failed: %w", err)
		}
	}
	return nil
}
