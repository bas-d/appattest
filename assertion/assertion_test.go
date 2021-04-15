package assertion

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestAssertionVerififcation(t *testing.T) {
	t.Run("Testing assertion", func(t *testing.T) {
		aar := AuthenticatorAssertionResponse{}
		if err := json.Unmarshal([]byte(assertion), &aar); err != nil {
			t.Fatal(err)
		}

		decodedPk, err := hex.DecodeString(publicKey)
		if err != nil {
			t.Fatalf("Could not decode public key: %+s", publicKey)
		}
		_, err = aar.Verify("assertion-test", "35MFYY2JY5.co.chiff.attestation-test", 0, decodedPk)
		if err != nil {
			t.Fatalf("Not valid: %+v", err)
		}
	})
}

const publicKey = "0437c404fa2bbf8fbcf4ee7080573d5fa80c4f6cc3a22f7db43af92c394e7cd1c880c95ab422972625e8e673af1bda2b096654e9b602895601f925bb5941c53082"
const assertion = `{ 
	"assertion": "omlzaWduYXR1cmVYRzBFAiEAyC5S3pcvtSpmTfNSd8aJRJCQ6PbN7Dnv_oPkZNMLeIwCIBmxCHXKYyGswzp_LwOxoL18puHooxudXWqDgtTvRomdcWF1dGhlbnRpY2F0b3JEYXRhWCV87ytV2nJBCLqRJ5b2df8AvnHVLa4mj6aI00ym0n9wdEAAAAAD",
	"clientData": "eyJjaGFsbGVuZ2UiOiJhc3NlcnRpb24tdGVzdCJ9"
}`
