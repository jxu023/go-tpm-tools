package client

// This file just re-exports functions from client/import_certify.go so that we can unit test-them

import (
	rpb "github.com/google/go-tpm-tools/proto/register_credential"
	tpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func EKPub(tpm transport.TPM) ([]byte, error) {
	return ekPub(tpm)
}
func CreateCertifiedAKBlob(tpm transport.TPM, req *tpb.ImportBlob, keyAlgo tpm2.TPMAlgID) (*rpb.CertifiedBlob, error) {
	return createCertifiedAKBlob(tpm, req, keyAlgo)
}
