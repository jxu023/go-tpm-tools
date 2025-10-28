package client

import (
	"bytes"
	"fmt"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/report"
	sabi "github.com/google/go-sev-guest/abi"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	rpb "github.com/google/go-tpm-tools/proto/register_credential"
	tpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Customize the behavior of MakeSVSMAttestation.
type SVSMOpts struct {
	// Wrapped HMAC representing a challenge to be solved to prove co-residence of the to be created AK.
	Blob *tpb.ImportBlob
	// Desired key algorithm for the created AK.
	AKAlgo tpm2.TPMAlgID
	// 64 byte nonce to be mixed into the REPORT_DATA field of the SNP attestation report.
	TEENonce []byte
	// Configfs client to use for retrieving the attestation report, certificates, and SVSM service manifest.
	CongfigfsClient configfsi.Client
}

// MakeSVSMAttestation creates a SevSnpSvsmAttestation containing all the information needed to verify the SVSM e-vTPM.
func MakeSVSMAttestation(tpm transport.TPM, opts *SVSMOpts) (*rpb.SevSnpSvsmAttestation, error) {
	var snpNonce [sabi.ReportDataSize]byte
	if len(opts.TEENonce) != sabi.ReportDataSize {
		return nil, fmt.Errorf("the teeNonce size is %d. SEV-SNP device requires 64", len(opts.TEENonce))
	}
	copy(snpNonce[:], opts.TEENonce)

	certified, err := createCertifiedAKBlob(tpm, opts.Blob, opts.AKAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create certified ak blob: %w", err)
	}
	tsmBlobs, err := getSVSMBlobs(opts.CongfigfsClient, snpNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get configfs-tsm blobs for SVSM attestation report: %w", err)
	}
	report, err := sabi.ReportToProto(tsmBlobs.OutBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to convert attestation report to proto: %w", err)
	}

	certs, err := getCertificates(opts.CongfigfsClient, snpNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificates from configfs-tsm: %w", err)
	}

	ekpub, err := ekPub(tpm)
	if err != nil {
		return nil, err
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
func getCertificates(configfs configfsi.Client, reportData [sabi.ReportDataSize]byte) (*sevpb.CertificateChain, error) {
	resp, err := report.Get(configfs, &report.Request{
		InBlob:     reportData[:],
		GetAuxBlob: true,
		Privilege: &report.Privilege{
			Level: uint(leastPrivilegedVMPL),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certififcates")
	}
	extended, err := sabi.ExtendedPlatformCertTable(resp.AuxBlob)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate table: %v", err)
	}
	table := new(sabi.CertTable)
	if err := table.Unmarshal(extended); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificates: %v", err)
	}
	return table.Proto(), nil
}

func getSVSMBlobs(configfs configfsi.Client, reportData [sabi.ReportDataSize]byte) (*report.Response, error) {
	resp, err := report.Get(configfs, &report.Request{
		InBlob:          reportData[:],
		ServiceProvider: svsmServiceProvider,
		ServiceGuid:     svsmServiceGUID,
	})
	if err != nil {
		return nil, fmt.Errorf("could not get SVSM attestation report: %v", err)
	}
	return resp, nil
}
