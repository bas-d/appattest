package utils

import (
	"encoding/json"
	"testing"
)

type Base64JSON struct {
	Unpadded URLEncodedBase64 `json:"unpadded"`
	Padded   URLEncodedBase64 `json:"padded"`
}

func TestUnmarshallingBase64Encoded(t *testing.T) {
	obj := Base64JSON{}
	padded := "paddeddata"
	unpadded := "unpaddeddata"
	if err := json.Unmarshal([]byte(base64JSON), &obj); err != nil {
		t.Fatal(err)
	}
	if padded != string(obj.Padded) {
		t.Fatalf("Padded data does not match: %s", obj.Padded)
	}
	if unpadded != string(obj.Unpadded) {
		t.Fatalf("Unpadded data does not match: %s", obj.Padded)
	}
}

const base64JSON = `{ 
	"unpadded": "dW5wYWRkZWRkYXRh",
	"padded": "cGFkZGVkZGF0YQ=="
}`
