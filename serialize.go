package main

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/cryptobyte"
)

type KeyTemplate struct {
	private tpm2.TPM2BPrivate
	public  tpm2.TPMTPublic
	seed    []byte
}

func Encode(k *KeyTemplate) []byte {
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, bytes := range [][]byte{
			tpm2.Marshal(k.private),
			tpm2.Marshal(tpm2.New2B(k.public)),
			k.seed,
		} {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(bytes))
			})
		}
	})
	return b.BytesOrPanic()
}

func Decode(b []byte) (*KeyTemplate, error) {
	var k KeyTemplate
	s := cryptobyte.String(b)
	if !s.ReadUint8LengthPrefixed(&s) {
		return nil, errors.New("no sequence 1")
	}

	// Reads the outer length of our 3 value pack
	var value cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&value) {
		return nil, errors.New("no sequence 2")
	}

	// Private portion
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](value)
	if err != nil {
		return nil, fmt.Errorf("could not parse private section of key: %v", err)
	}
	k.private = *private

	if !s.ReadUint8LengthPrefixed(&value) {
		return nil, errors.New("no sequence 3")
	}

	// Public portion
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](value)
	if err != nil {
		return nil, errors.New("could not parse public section of key")
	}
	publicT, err := public.Contents()
	if err != nil {
		return nil, errors.New("could not parse public section of key")
	}
	k.public = *publicT

	// Seed portion
	if !s.ReadUint8LengthPrefixed(&value) {
		return nil, errors.New("no sequence 4")
	}
	k.seed = value

	return &k, nil
}
