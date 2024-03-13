package main

import (
	"context"
	"log"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/psanford/ctapkey"
	"github.com/psanford/ctapkey/pinentry"
)

func main() {

	tpm, err := transport.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}

	signer := &TPMKey{tpm}

	s := ctapkey.Server{
		Signer:   signer,
		PinEntry: pinentry.New(),
		Logger:   log.Default(),
	}

	err = s.Run(context.Background())
	if err != nil {
		panic(err)
	}
}
