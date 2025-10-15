package client

import (
	"fmt"

	rpb "github.com/google/go-tpm-tools/proto/register_credential"
	tpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// This file aims to implement the attester side of https://trustedcomputinggroup.org/wp-content/uploads/EK-Based-Key-Attestation-with-TPM-Firmware-Version-V1-RC1_9July2025.pdf#page=8
// For reference: https://github.com/TrustedComputingGroup/tpm-fw-attestation-reference-code

func ekPub(tpm transport.TPM) ([]byte, error) {
	cp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(tpm)

	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{
		FlushHandle: cp.ObjectHandle,
	}.Execute(tpm)

	return cp.OutPublic.Bytes(), nil
}

func makeAK(tpm transport.TPM, keyAlgo tpm2.TPMAlgID) (*tpm2.CreatePrimaryResponse, error) {
	var public []byte
	var err error
	if keyAlgo == tpm2.TPMAlgECC {
		public, err = AKTemplateECC().Encode()
	}
	if keyAlgo == tpm2.TPMAlgRSA {
		public, err = AKTemplateRSA().Encode()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create AK: %w", err)
	}
	cp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.BytesAs2B[tpm2.TPMTPublic](public),
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	return cp, nil
}

func createCertifiedAKBlob(tpm transport.TPM, req *tpb.ImportBlob, keyAlgo tpm2.TPMAlgID) (*rpb.CertifiedBlob, error) {
	// SVSM currently only supports attesting an RSA EK.
	ek, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA EK: %w", err)
	}

	// Import the restricted HMAC key.
	imported, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: ek.ObjectHandle,
			Name:   ek.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		ObjectPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](req.GetPublicArea()),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: req.GetDuplicate()},
		InSymSeed:    tpm2.TPM2BEncryptedSecret{Buffer: req.GetEncryptedSeed()},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to import blob: %w", err)
	}

	// Load the imported HMAC key.
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: ek.ObjectHandle,
			Name:   ek.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](req.GetPublicArea()),
		InPrivate: imported.OutPrivate,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to load HMAC: %w", err)
	}

	tpm2.FlushContext{
		FlushHandle: ek.ObjectHandle,
	}.Execute(tpm)

	defer tpm2.FlushContext{
		FlushHandle: loaded.ObjectHandle,
	}.Execute(tpm)

	ak, err := makeAK(tpm, keyAlgo)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{
		FlushHandle: ak.ObjectHandle,
	}.Execute(tpm)

	// Certify a newly created AK.
	certified, err := tpm2.Certify{
		ObjectHandle: tpm2.NamedHandle{
			Handle: ak.ObjectHandle,
			Name:   ak.Name,
		},
		SignHandle: tpm2.NamedHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
		},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to certify blob: %w", err)
	}

	return &rpb.CertifiedBlob{
		AkPub:       ak.OutPublic.Bytes(),
		CertifyInfo: certified.CertifyInfo.Bytes(),
		RawSig:      tpm2.Marshal(certified.Signature),
	}, nil
}

func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}
