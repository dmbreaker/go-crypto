package cryptostore

import (
	"github.com/pkg/errors"

	crypto "github.com/tendermint/go-crypto"
	"github.com/tendermint/go-crypto/bcrypt"
)

const (
	// BcryptCost is as parameter to increase the resistance of the
	// encoded keys to brute force password guessing
	//
	// Jae: 14 is good today (2016)
	//
	// Ethan: loading the key (at each signing) takes a second on my desktop,
	// this is hard for laptops and deadly for mobile. You can raise it again,
	// but for now, I will make this usable
	//
	// TODO: review value
	bcryptCost = 12
)

var (
	// SecretBox uses the algorithm from NaCL to store secrets securely
	SecretBox Encoder = secretbox{}
	// Noop doesn't do any encryption, should only be used in test code
	Noop Encoder = noop{}
)

// Encoder is used to encrypt any key with a passphrase for storage.
//
// This should use a well-designed symetric encryption algorithm
type Encoder interface {
	Encrypt(privKey crypto.PrivKey, passphrase string) (saltBytes, encBytes []byte, err error)
	Decrypt(saltBytes, encBytes []byte, passphrase string) (privKey crypto.PrivKey, err error)
}

type secretbox struct{}

func (e secretbox) Encrypt(privKey crypto.PrivKey,
	passphrase string) (saltBytes, encBytes []byte, err error) {

	if passphrase == "" {
		return nil, nil, errors.Wrap(err, "Password cannot be an empty string.")
	}

	saltBytes = crypto.CRandBytes(16)
	// TODO parameterize.  14 is good today (2016)
	key, err := bcrypt.GenerateFromPassword(saltBytes, []byte(passphrase), bcryptCost)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Couldn't generate bcrypt key from passphrase.")
	}
	key = crypto.Sha256(key) // Get 32 bytes
	return saltBytes, crypto.EncryptSymmetric(privKey.Bytes(), key), nil
}

func (e secretbox) Decrypt(saltBytes, encBytes []byte,
	passphrase string) (privKey crypto.PrivKey, err error) {

	privKeyBytes := encBytes
	// NOTE: Some keys weren't encrypted with a passphrase and hence we have the conditional
	if passphrase != "" {
		var key []byte
		var err error
		if saltBytes == nil {
			key = []byte(passphrase)
		} else {
			// TODO parameterize.  14 is good today (2016)
			key, err = bcrypt.GenerateFromPassword(saltBytes, []byte(passphrase),
				bcryptCost)
			if err != nil {
				return crypto.PrivKey{}, errors.Wrap(err, "Invalid Passphrase")
			}
		}

		key = crypto.Sha256(key) // Get 32 bytes
		privKeyBytes, err = crypto.DecryptSymmetric(encBytes, key)
		if err != nil {
			return crypto.PrivKey{}, errors.Wrap(err, "Invalid Passphrase")
		}
	}
	privKey, err = crypto.PrivKeyFromBytes(privKeyBytes)
	if err != nil {
		return crypto.PrivKey{}, errors.Wrap(err, "Couldn't get privKey from bytes")
	}
	return privKey, nil
}

type noop struct{}

func (n noop) Encrypt(key crypto.PrivKey,
	passphrase string) (saltBytes []byte, encBytes []byte, err error) {

	return []byte{}, key.Bytes(), nil
}

func (n noop) Decrypt(saltBytes []byte, encBytes []byte,
	passphrase string) (privKey crypto.PrivKey, err error) {

	return crypto.PrivKeyFromBytes(encBytes)
}
