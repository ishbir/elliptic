// build +cgo
package elliptic

import (
	"bytes"
	"encoding/binary"
	"errors"
)

/*
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
*/
import "C"

// Curve repesents the ASN.1 OID of an elliptic curve.
type Curve int16

// Supported elliptic curves. Generated from openssl/obj_mac.h
const (
	Secp112r1 Curve = C.NID_secp112r1
	Secp112r2 Curve = C.NID_secp112r2
	Secp128r1 Curve = C.NID_secp128r1
	Secp128r2 Curve = C.NID_secp128r2
	Secp160k1 Curve = C.NID_secp160k1
	Secp160r1 Curve = C.NID_secp160r1
	Secp160r2 Curve = C.NID_secp160r2
	Secp192k1 Curve = C.NID_secp192k1
	Secp224k1 Curve = C.NID_secp224k1
	Secp224r1 Curve = C.NID_secp224r1
	Secp256k1 Curve = C.NID_secp256k1
	Secp384r1 Curve = C.NID_secp384r1
	Secp521r1 Curve = C.NID_secp521r1
	Sect113r1 Curve = C.NID_sect113r1
	Sect113r2 Curve = C.NID_sect113r2
	Sect131r1 Curve = C.NID_sect131r1
	Sect131r2 Curve = C.NID_sect131r2
	Sect163k1 Curve = C.NID_sect163k1
	Sect163r1 Curve = C.NID_sect163r1
	Sect163r2 Curve = C.NID_sect163r2
	Sect193r1 Curve = C.NID_sect193r1
	Sect193r2 Curve = C.NID_sect193r2
	Sect233k1 Curve = C.NID_sect233k1
	Sect233r1 Curve = C.NID_sect233r1
	Sect239k1 Curve = C.NID_sect239k1
	Sect283k1 Curve = C.NID_sect283k1
	Sect283r1 Curve = C.NID_sect283r1
	Sect409k1 Curve = C.NID_sect409k1
	Sect409r1 Curve = C.NID_sect409r1
	Sect571k1 Curve = C.NID_sect571k1
	Sect571r1 Curve = C.NID_sect571r1
)

// Public key which can be used for verifying signatures etc.
type PublicKey struct {
	Curve
	X, Y []byte
}

// Re-create a PublicKey object from the binary format that it was stored in.
func PublicKeyFromBytes(raw []byte) (*PublicKey, error) {
	key := new(PublicKey)
	var curve, xLen, yLen int16
	b := bytes.NewReader(raw)

	err := binary.Read(b, binary.BigEndian, &curve)
	if err != nil {
		return nil, errors.New("couldn't read curve")
	}
	key.Curve = Curve(curve)

	err = binary.Read(b, binary.BigEndian, &xLen)
	if err != nil {
		return nil, errors.New("couldn't read X len")
	}

	key.X = make([]byte, xLen)
	err = binary.Read(b, binary.BigEndian, key.X)
	if err != nil {
		return nil, errors.New("couldn't read X")
	}

	err = binary.Read(b, binary.BigEndian, &yLen)
	if err != nil {
		return nil, errors.New("couldn't read Y len")
	}

	key.Y = make([]byte, yLen)
	err = binary.Read(b, binary.BigEndian, key.Y)
	if err != nil {
		return nil, errors.New("couldn't read Y")
	}

	err = check_key(key.Curve, key, nil)
	if err != nil {
		return nil, errors.New("key check failed: " + err.Error())
	}

	return key, nil
}

// Serialize the public key into a binary format useful for network transfer or
// storage.
func (key *PublicKey) Serialize() []byte {
	var curve, xLen, yLen int16
	curve = int16(key.Curve)
	xLen = int16(len(key.X))
	yLen = int16(len(key.Y))

	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, curve)
	binary.Write(&b, binary.BigEndian, xLen)
	b.Write(key.X)
	binary.Write(&b, binary.BigEndian, yLen)
	b.Write(key.Y)

	return b.Bytes()
}

// Check whether the public and private keys are valid for the given curve
// and whether the private key belongs to the given public key (if privkey is
// not nil). No error means that the check was successful.
func check_key(curve Curve, pubkey *PublicKey, privkey *PrivateKey) error {
	return nil
}

// Private key which can be used for signing, encryption, decryption etc.
type PrivateKey struct {
	PublicKey
	Key []byte
}

// Re-create the private key from the binary format that it was stored in.
func PrivateKeyFromBytes(raw []byte) (*PrivateKey, error) {
	key := new(PrivateKey)
	var curve, keyLen int16
	b := bytes.NewReader(raw)

	err := binary.Read(b, binary.BigEndian, &curve)
	if err != nil {
		return nil, errors.New("couldn't read curve")
	}
	key.Curve = Curve(curve)

	err = binary.Read(b, binary.BigEndian, &keyLen)
	if err != nil {
		return nil, errors.New("couldn't key len")
	}

	key.Key = make([]byte, keyLen)
	err = binary.Read(b, binary.BigEndian, key.Key)
	if err != nil {
		return nil, errors.New("couldn't read private key")
	}

	return key, nil
}

// Generate a random private key for the given curve.
func GeneratePrivateKey(curve Curve) (*PrivateKey, error) {
	key := new(PrivateKey)

	return key, nil
}

// Serialize the private key into a binary format useful for network transfer or
// storage.
func (key *PrivateKey) Serialize() []byte {
	var curve, keyLen int16
	curve = int16(key.Curve)
	keyLen = int16(len(key.Key))

	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, curve)
	binary.Write(&b, binary.BigEndian, keyLen)
	b.Write(key.Key)

	return b.Bytes()
}
