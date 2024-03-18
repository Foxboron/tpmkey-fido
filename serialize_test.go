package main

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func must2BPrivate(data []byte) tpm2.TPM2BPrivate {
	return tpm2.TPM2BPrivate{
		Buffer: data,
	}
}

func TestDecode(t *testing.T) {
	for _, tt := range []struct {
		key *KeyTemplate
	}{
		{
			key: &KeyTemplate{
				private: must2BPrivate([]byte("test")),
				public:  tpm2.ECCSRKTemplate,
				seed:    []byte("seed"),
			},
		},
	} {

		enc := Encode(tt.key)
		_, err := DecodeLen(enc)
		if err != nil {
			t.Fatalf("failed decoding: %v", err)
		}
	}
}
