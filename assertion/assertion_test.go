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
		err = aar.Verify([]byte("attestation-test"), "35MFYY2JY5.co.chiff.attestation-test", 0, decodedPk)
		if err != nil {
			t.Fatalf("Not valid: %+v", err)
		}
	})
}

const publicKey = "042bc5badb424b7f24b4f70a9e7e6f54309d26800c16cf10edf78820109c64a429a603244d57c2ad7156a2213a47eb674910c630706a56d170ccb3758e80d58218"

const assertion = `{ 
	"assertion": "omlzaWduYXR1cmVYRjBEAiBjhWzVClZBa6I38V6cWWK22tE6asBfU0SQiGa3xTsdzgIgA-vso5QWvul-w0mNZnADdTZ7CTgIRmAzLyF0UfoEHo5xYXV0aGVudGljYXRvckRhdGFYJXzvK1XackEIupEnlvZ1_wC-cdUtriaPpojTTKbSf3B0QAAAAAI",
	"clientData": "YXR0ZXN0YXRpb24tdGVzdA"
}`
