package client_test

import (
	"crypto/sha512"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/faketsm"
	sabi "github.com/google/go-sev-guest/abi"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	sgtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"google.golang.org/protobuf/encoding/prototext"
)

func TestMakeSVSMAttestation(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	tpm := transport.FromReadWriteCloser(rwc)

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get EK: %v", err)
	}
	defer ek.Close()
	ekBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode EK pub: %v", err)
	}
	ekPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](ekBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal EK pub: %v", err)
	}
	blob, secret, err := server.CreateRestrictedHMACBlob(ekPub)
	if err != nil {
		t.Fatalf("failed to create restricted hmac blob: %v", err)
	}

	var snpNonce [sabi.ReportDataSize]byte = [sabi.ReportDataSize]byte{0}
	h := sha512.New()
	h.Write(snpNonce[:])
	h.Write(ekBytes)
	configfs := makeFakeConfigfs(h.Sum(nil), ekBytes, 0)
	if err != nil {
		t.Fatalf("failed to make fake configfsi client: %v", err)
	}
	attestation, err := client.MakeSVSMAttestation(tpm, &client.SVSMOpts{
		TEENonce:        snpNonce[:],
		Blob:            blob,
		AKAlgo:          tpm2.TPMAlgECC,
		CongfigfsClient: configfs,
	})
	if err != nil {
		t.Fatalf("failed to make SVSM attestation: %v", err)
	}

	err = server.VerifySVSMAttestation(&server.VerifySVSMOpts{
		TEENonce:    snpNonce[:],
		Attestation: attestation,
		Secret:      secret,
		// don't verify signatures for the fake certificates
		VerifyOpts: nil,
	})
	if err != nil {
		t.Fatalf("failed to verify svsm attestation: %v", err)
	}
}

func TestSvsmAttestationsErrors(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	tpm := transport.FromReadWriteCloser(rwc)

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get EK: %v", err)
	}
	defer ek.Close()
	ekBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode EK pub: %v", err)
	}
	ekPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](ekBytes)
	if err != nil {
		t.Fatalf("failed to unmarshal EK pub: %v", err)
	}
	blob, secret, err := server.CreateRestrictedHMACBlob(ekPub)
	if err != nil {
		t.Fatalf("failed to create restricted hmac blob: %v", err)
	}

	var snpNonce [sabi.ReportDataSize]byte = [sabi.ReportDataSize]byte{0}
	h := sha512.New()
	h.Write(snpNonce[:])
	h.Write(ekBytes)
	goodReportData := h.Sum(nil)
	goodVmpl := 0
	testcases := []struct {
		name          string
		getConfigfs   func(t *testing.T) configfsi.Client
		wantErrString string
	}{
		{
			name: "Bad report data",
			getConfigfs: func(t *testing.T) configfsi.Client {
				var snpNonce [sabi.ReportDataSize]byte = [sabi.ReportDataSize]byte{0}
				return makeFakeConfigfs(snpNonce[:], ekBytes, goodVmpl)
			},
			wantErrString: "report data does not match expected value",
		},
		{
			name: "Bad VMPL",
			getConfigfs: func(t *testing.T) configfsi.Client {
				return makeFakeConfigfs(goodReportData, ekBytes, 2)
			},
			wantErrString: "SVSM should be in VMPL0",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			attestation, err := client.MakeSVSMAttestation(tpm, &client.SVSMOpts{
				TEENonce:        snpNonce[:],
				Blob:            blob,
				AKAlgo:          tpm2.TPMAlgECC,
				CongfigfsClient: tc.getConfigfs(t),
			})
			if err != nil {
				t.Fatalf("failed to make SVSM attestation: %v", err)
			}

			err = server.VerifySVSMAttestation(&server.VerifySVSMOpts{
				TEENonce:    snpNonce[:],
				Attestation: attestation,
				Secret:      secret,
				// don't verify signatures for the fake certificates
				VerifyOpts: nil,
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErrString) {
				t.Errorf("got err: %v, want err containing: %q", err, tc.wantErrString)
			}
		})
	}
}

var emptyReportV4 = `
	version: 4
	policy: 0xa0000
	signature_algo: 1
	report_data: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
	family_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	image_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	measurement: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	host_data: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	id_key_digest: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	author_key_digest: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	report_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	report_id_ma: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	cpuid1eax_fms: 0
	chip_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	signature: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	`

func makeSnpAttestationReport(reportData []byte, vmpl int) ([]byte, error) {
	reportProto := &sevpb.Report{}
	prototext.Unmarshal([]byte(emptyReportV4), reportProto)
	reportProto.ReportData = reportData
	reportProto.Vmpl = uint32(vmpl)
	return sabi.ReportToAbiBytes(reportProto)
}

func makeFakeConfigfs(reportData []byte, ekPub []byte, vmpl int) configfsi.Client {
	report := faketsm.Report611(0)
	report.ReadAttr = readFS(reportData, ekPub, vmpl)
	configfs := &faketsm.Client{Subsystems: map[string]configfsi.Client{
		"report": report,
	}}

	return configfs
}

func makeFakeCerts() ([]byte, error) {
	b := &sgtest.AmdSignerBuilder{
		Extras: map[string][]byte{sabi.ExtraPlatformInfoGUID: []byte("test")},
	}
	s, err := b.TestOnlyCertChain()
	if err != nil {
		return nil, fmt.Errorf("failed to make test cert chain: %v", err)
	}
	certBytes, err := s.CertTableBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize test cert chain: %v", err)
	}
	return certBytes, nil
}

func readFS(reportData []byte, ekPub []byte, vmpl int) func(*faketsm.ReportEntry, string) ([]byte, error) {
	return func(e *faketsm.ReportEntry, attr string) ([]byte, error) {
		switch attr {
		case "provider":
			return []byte("fake\n"), nil
		case "auxblob":
			return makeFakeCerts()
		case "outblob":
			return makeSnpAttestationReport(reportData, vmpl)
		case "privlevel_floor":
			return []byte(strconv.Itoa(vmpl)), nil
		case "manifestblob":
			return ekPub, nil
		}
		return nil, os.ErrNotExist
	}
}
