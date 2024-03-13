package main

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type KeyTemplate struct {
	private tpm2.TPM2BPrivate
	public  tpm2.TPMTPublic
	seed    []byte
}

func Encode(k *KeyTemplate) []byte {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		privb := tpm2.Marshal(k.private)
		fmt.Printf("private length: %v\n", len(privb))
		b.AddASN1OctetString(privb)
		public := tpm2.New2B(k.public)
		pubb := tpm2.Marshal(public)
		fmt.Printf("public length: %v\n", len(pubb))
		b.AddASN1OctetString(pubb)
		b.AddASN1OctetString(k.seed)
	})
	return b.BytesOrPanic()
}

func Decode(b []byte) (*KeyTemplate, error) {
	fmt.Println(len(b))
	var k KeyTemplate
	s := cryptobyte.String(b)
	if !s.ReadASN1(&s, asn1.SEQUENCE) {
		return nil, errors.New("no sequence")
	}

	var privkey cryptobyte.String
	if !s.ReadASN1(&privkey, asn1.OCTET_STRING) {
		return nil, errors.New("could not parse private section")
	}
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privkey)
	if err != nil {
		return nil, fmt.Errorf("could not parse private section of key: %v", err)
	}

	fmt.Printf("private length: %v\n", len(privkey))
	k.private = *private

	fmt.Println(len(s))

	var pubkey cryptobyte.String
	if !s.ReadASN1(&pubkey, asn1.OCTET_STRING) {
		return nil, errors.New("could not parse pubkey")
	}
	fmt.Printf("public length: %v\n", len(pubkey))
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubkey)
	if err != nil {
		return nil, errors.New("could not parse public section of key")
	}
	publicT, err := public.Contents()
	if err != nil {
		return nil, errors.New("could not parse public section of key")
	}
	k.public = *publicT

	var seed cryptobyte.String
	if !s.ReadASN1(&seed, asn1.OCTET_STRING) {
		return nil, errors.New("could not parse seed")
	}
	k.seed = seed

	return &k, nil
}
