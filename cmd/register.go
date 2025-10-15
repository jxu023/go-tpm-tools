package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2"
	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-tpm-tools/client"
	rpb "github.com/google/go-tpm-tools/proto/register_credential"
	tpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
)

// this file implements TPM registration which for now is only used for SVSM e-vTPMs.
// It uses https://trustedcomputinggroup.org/wp-content/uploads/EK-Based-Key-Attestation-with-TPM-Firmware-Version-V1-RC1_9July2025.pdf#page=8
// which we call as import certify
// activate credential is not implemented yet.

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register an SVSM TPM AK",
	Long:  "Given an EK, we'll register a corresponding AK and prove that it's on the same TPM as the EK.",
	Args:  cobra.NoArgs,
}

var (
	secretOut string
	secretIn  string
)

func addSecretInputFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&secretIn, "secret-input", "",
		"specifies path to read the secret that was generated from create-challenge")
}

func addSecretOutputFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&secretOut, "secret-output", "",
		"specifies path to write the secret to")
}

var createChallengeCmd = &cobra.Command{
	Use:   "create-challenge",
	Short: "Create a challenge for the client to register the EK",
	Long: `Given an EK public key in TPM2 wire format, create a challenge for the client
	to register the EK.  and save the ChallengeSecret but don't share it with the
	client.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ekpub, err := ReadTPM2WireFormatKey(dataInput())
		if err != nil {
			return err
		}

		challenge, secret, err := server.CreateChallenge(ekpub)
		if err != nil {
			return fmt.Errorf("could not create challenge: %s", err)
		}
		writeProtoToOutput(challenge)
		_, err = openForWrite(secretOut).Write(secret)
		if err != nil {
			return fmt.Errorf("could not write secret: %s", err)
		}

		return nil
	},
}

var solveChallengeCmd = &cobra.Command{
	Use:   "solve-challenge",
	Short: "Solve a challenge from the TPM EK",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var challenge *tpb.ImportBlob = &tpb.ImportBlob{}
		err := readProtoFromPath(input, challenge)
		if err != nil {
			return fmt.Errorf("could not read challnge: %s", err)
		}

		rwc, err := openImpl()
		if err != nil {
			return fmt.Errorf("could not open TPM: %s", err)
		}
		defer rwc.Close()

		tpm := transport.FromReadWriter(rwc)
		var reportData [sevabi.ReportDataSize]byte
		copy(reportData[:], teeNonce)
		solved, err := client.MakeSVSMAttestation(tpm, challenge, tpm2.TPMAlgID(keyAlgo), reportData)
		if err != nil {
			return fmt.Errorf("could not solve challenge: %s", err)
		}
		writeProtoToOutput(solved)
		return nil
	},
}

var verifyChallengeCmd = &cobra.Command{
	Use:   "verify-challenge",
	Short: "Verify a challenge for the SVSM TPM's EK and its binding to the SNP attestation report",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var attestation *rpb.SevSnpSvsmAttestation = &rpb.SevSnpSvsmAttestation{}
		err := readProtoFromPath(input, attestation)
		if err != nil {
			return err
		}

		if secretIn == "" {
			return fmt.Errorf("secret-input must be specified")
		}
		secret, err := readBytes(secretIn)
		if err != nil {
			return fmt.Errorf("could not read secret: %s", err)
		}

		var reportData [sevabi.ReportDataSize]byte
		copy(reportData[:], teeNonce)
		err = server.VerifySVSMAttestation(reportData, attestation, secret)
		if err != nil {
			return fmt.Errorf("could not verify attestation: %s", err)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(registerCmd)
	challengeCommands := []*cobra.Command{
		createChallengeCmd,
		solveChallengeCmd,
		verifyChallengeCmd,
	}
	for _, cmd := range challengeCommands {
		registerCmd.AddCommand(cmd)
		addOutputFlag(cmd)
		addFormatFlag(cmd)
		addInputFlag(cmd)
	}

	addSecretOutputFlag(createChallengeCmd)
	addSecretInputFlag(verifyChallengeCmd)
	addTeeNonceflag(solveChallengeCmd)
	addTeeNonceflag(verifyChallengeCmd)
	addPublicKeyAlgoFlag(solveChallengeCmd)
}
