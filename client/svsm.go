package client

import (
	"bytes"
	"fmt"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2"
	sabi "github.com/google/go-sev-guest/abi"
	sg "github.com/google/go-sev-guest/client"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	rpb "github.com/google/go-tpm-tools/proto/register_credential"
	tpb "github.com/google/go-tpm-tools/proto/tpm"
)

// MakeSVSMAttestation creates a SevSnpSvsmAttestation containing all the information needed to verify the SVSM e-vTPM.
func MakeSVSMAttestation(tpm transport.TPM, req *tpb.ImportBlob, keyAlgo tpm2.TPMAlgID, teeNonce [sabi.ReportDataSize]byte) (*rpb.SevSnpSvsmAttestation, error) {
	certified, err := SolveChallengeImportCertify(tpm, req, keyAlgo)
	if err != nil {
		return nil, fmt.Errorf("SolveChallengeImportCertify() = %w", err)
	}
	tsmBlobs, err := getSVSMBlobs(teeNonce)
	if err != nil {
		return nil, fmt.Errorf("getSVSMBlobs() = %w", err)
	}
	report, err := sabi.ReportToProto(tsmBlobs.OutBlob)
	if err != nil {
		return nil, fmt.Errorf("ReportToProto() = %w", err)
	}

	certs, err := getCertificates(teeNonce)
	if err != nil {
		return nil, fmt.Errorf("getReportWithCerts() = %w", err)
	}

	ekpub, err := ekPub(tpm)
	if err != nil {
		return nil, fmt.Errorf("ekPub() = %w", err)
	}
	if !bytes.Equal(ekpub, tsmBlobs.ManifestBlob) {
		return nil, fmt.Errorf("service manifest does not match EK pub")
	}

	return &rpb.SevSnpSvsmAttestation{
		CertifiedBlob:       certified,
		VtpmServiceManifest: tsmBlobs.ManifestBlob,
		SevSnpAttestation: &sevpb.Attestation{
			Report:           report,
			CertificateChain: certs,
		},
	}, nil
}

const (
	svsmServiceProvider = "svsm"
	// GUID for SVSM vTPM attestation.
	svsmServiceGUID     = "c476f1eb-0123-45a5-9641-b4e7dde5bfe3"
	leastPrivilegedVMPL = 3
)

// SVSM currently doesn't support certificates in its attestation report, so here we collect
// the certificate chain by requesting a report without SVSM to get the cached certificates.
func getCertificates(reportData [sabi.ReportDataSize]byte) (*sevpb.CertificateChain, error) {
	qp, err := sg.GetLeveledQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get LeveledQuoteProvider(): %v", err)
	}
	rawWithCerts, err := qp.GetRawQuoteAtLevel(reportData, leastPrivilegedVMPL)
	if err != nil {
		return nil, fmt.Errorf("failed to GetRawQuoteAtLevel(): %v", err)
	}
	reportWithCerts, err := sabi.ReportCertsToProto(rawWithCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SEV-SNP report with certs: %v", err)
	}
	return reportWithCerts.GetCertificateChain(), nil
}

func getSVSMBlobs(reportData [sabi.ReportDataSize]byte) (*report.Response, error) {
	req := &report.Request{
		InBlob:          reportData[:],
		ServiceProvider: svsmServiceProvider,
		ServiceGuid:     svsmServiceGUID,
	}

	resp, err := linuxtsm.GetReport(req)
	if err != nil {
		return nil, fmt.Errorf("could not get SVSM attestation report: %v", err)
	}
	return resp, nil
}
