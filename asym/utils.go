package asym

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
)

func PrintPublicKey(k *ecdsa.PublicKey) {
	pub, err := ExportPubKey(k)
	if err != nil {
		fmt.Printf("Failed to export public key: %s", err.Error())
	} else {
		fmt.Printf("Your public key: %x\n", pub)
	}
}

func GetPrivateKey(cmd string) (key *ecdsa.PrivateKey, err error) {
	if strings.Contains(cmd, "r") {
		s := string("Wrong flag 'r': random password is not allowed for private key import")
		fmt.Println(s)
		return nil, errors.New(s)
	}
	var hash2fa []byte
	if strings.Contains(cmd, "f") {
		hash2fa, err = common.LoadCertificate(true)
		if err != nil {
			return nil, err
		}
	}
	pass := common.GetPassword(cmd)
	for i := 0; i < len(pass) && i < len(hash2fa); i++ {
		pass[i] ^= hash2fa[i]
	}
	raw := keccak.Digest(pass, 32)
	key, err = ImportPrivateKey(raw)
	crutils.AnnihilateData(pass)
	crutils.AnnihilateData(raw)
	if err != nil {
		fmt.Printf("Failed to import private key: %s\n", err.Error())
	}
	return key, err
}

func GetPubKey() (key *ecdsa.PublicKey, raw []byte, err error) {
	raw = common.GetHexData("public key")
	err = CheckRawPubValidity(raw)
	if err != nil {
		fmt.Println(err)
		return
	}
	if raw != nil {
		key, err = ImportPubKey(raw)
		if err != nil {
			fmt.Printf("Error importing public key: %s\n", err.Error())
		}
	} else {
		err := errors.New("wrong input")
		fmt.Println(err.Error())
	}
	return key, raw, err
}

func CheckRawPubValidity(raw []byte) error {
	if len(raw) != PublicKeySize {
		return fmt.Errorf("Wrong public key size: %d vs. %d \n", len(raw), PublicKeySize)
	}
	zero := make([]byte, PublicKeySize)
	if !primitives.IsDeepNotEqual(raw, zero, PublicKeySize) {
		return errors.New("Wrong public key: too many zeroes")
	}
	return nil
}
