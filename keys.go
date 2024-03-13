package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

func CreateSRK(tpm transport.TPMCloser, seed, appparams []byte) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {

	info := append([]byte("tpmkey-fido-application-key"), appparams...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)

	eccpoint := &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: make([]byte, 32),
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: make([]byte, 32),
		},
	}

	if _, err := io.ReadFull(r, eccpoint.X.Buffer); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, eccpoint.Y.Buffer); err != nil {
		panic(err)
	}

	eccTmpl := tpm2.ECCSRKTemplate

	eccTmpl.Unique = tpm2.NewTPMUPublicID(
		tpm2.TPMAlgECC,
		eccpoint,
	)
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err := srk.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating primary key: %v", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}

	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

type TPMKey struct {
	tpm  transport.TPMCloser
	lock sync.Mutex
}

var baseTime = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

func (t *TPMKey) Counter() uint32 {
	unix := time.Now().Unix()
	return uint32(unix - baseTime.Unix())
}

func mkSeed() []byte {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// shadow the unexported interface from go-tpm
type handle interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}

func FlushHandle(tpm transport.TPM, h handle) {
	flushSrk := tpm2.FlushContext{FlushHandle: h}
	flushSrk.Execute(tpm)
}

func createECCKey(ecc tpm2.TPMECCCurve, sha tpm2.TPMAlgID) tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic] {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: sha,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: ecc,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
	})
}

func (t *TPMKey) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	seed := mkSeed()

	srkHandle, srkPublic, err := CreateSRK(t.tpm, seed, applicationParam)
	if err != nil {
		return []byte{}, big.NewInt(0), big.NewInt(0), err
	}
	defer FlushHandle(t.tpm, srkHandle)

	tmpl := createECCKey(tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	createKey := tpm2.Create{
		ParentHandle: srkHandle,
		InPublic:     tmpl,
	}

	var createRsp *tpm2.CreateResponse
	createRsp, err = createKey.Execute(t.tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return []byte{}, big.NewInt(0), big.NewInt(0), fmt.Errorf("failed creating TPM key: %v", err)
	}

	pub, err := createRsp.OutPublic.Contents()
	if err != nil {
		return []byte{}, big.NewInt(0), big.NewInt(0), err
	}

	key := &KeyTemplate{
		private: createRsp.OutPrivate,
		public:  *pub,
		seed:    seed,
	}

	b := Encode(key)

	eccdeets, err := pub.Unique.ECC()
	if err != nil {
		log.Fatal(err)
	}

	x := new(big.Int).SetBytes(eccdeets.X.Buffer)
	y := new(big.Int).SetBytes(eccdeets.Y.Buffer)

	return b, x, y, nil
}

// from crypto/ecdsa
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// from crypto/ecdsa
func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

func (t *TPMKey) SignASN1(keyb, applicationParam, digest []byte) ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	key, err := Decode(keyb)
	if err != nil {
		log.Fatal(err)
	}

	srkHandle, srkPublic, err := CreateSRK(t.tpm, key.seed, applicationParam)
	if err != nil {
		return []byte{}, nil
	}
	defer FlushHandle(t.tpm, srkHandle)

	loadBlobCmd := tpm2.Load{
		ParentHandle: srkHandle,
		InPrivate:    key.private,
		InPublic:     tpm2.New2B(key.public),
	}
	loadBlobRsp, err := loadBlobCmd.Execute(t.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed getting handle: %v", err)
	}
	defer FlushHandle(t.tpm, loadBlobRsp.ObjectHandle)

	sign := tpm2.Sign{
		KeyHandle: &tpm2.AuthHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(t.tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %v", err)
	}

	eccsig, err := rspSign.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("failed getting signature: %v", err)
	}
	return encodeSignature(eccsig.SignatureR.Buffer, eccsig.SignatureS.Buffer)
}
