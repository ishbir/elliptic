package elliptic

// build +cgo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

/*
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

static int BN_num_bytes_not_a_macro(BIGNUM* arg) {
	return BN_num_bytes(arg);
}
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

	err = check_keys(key.Curve, key, nil)
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

// Gets an EC_KEY object from the given public and private keys. This function
// was created because code for this was getting repeated in other functions.
func getEC_KEY(curve Curve, pubkey *PublicKey, privkey *PrivateKey) (*C.EC_KEY,
	error) {
	// initialization
	key := C.EC_KEY_new_by_curve_name(C.int(curve))
	if key == nil {
		return nil, errors.New("[OpenSSL] EC_KEY_new_by_curve_name FAIL")
	}
	// instruct garbage collector to free EC_KEY
	runtime.SetFinalizer(key, func(k *C.EC_KEY) {
		C.EC_KEY_free(k)
	})

	// convert bytes to BIGNUMs
	pub_key_x := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&pubkey.X[0])),
		C.int(len(pubkey.X)), nil)
	defer C.BN_free(pub_key_x)
	pub_key_y := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&pubkey.Y[0])),
		C.int(len(pubkey.Y)), nil)
	defer C.BN_free(pub_key_y)

	// also add private key if it exists
	if privkey != nil {
		priv_key := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&privkey.Key[0])),
			C.int(len(privkey.Key)), nil)
		defer C.BN_free(priv_key)

		if C.EC_KEY_set_private_key(key, priv_key) == C.int(0) {
			return nil, errors.New("[OpenSSL] EC_KEY_set_private_key FAIL")
		}
	}

	group := C.EC_KEY_get0_group(key)
	pub_key := C.EC_POINT_new(group)
	defer C.EC_POINT_free(pub_key)

	// set coordinates to get pubkey and then set pubkey
	if C.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x,
		pub_key_y, nil) == C.int(0) {
		return nil, errors.New("[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL")
	}
	if C.EC_KEY_set_public_key(key, pub_key) == C.int(0) {
		return nil, errors.New("[OpenSSL] EC_KEY_set_public_key FAIL")
	}
	// validate the key
	if C.EC_KEY_check_key(key) == C.int(0) {
		return nil, errors.New("[OpenSSL] EC_KEY_check_key FAIL")
	}

	return key, nil
}

// Check whether the public and private keys are valid for the given curve
// and whether the private key belongs to the given public key (if privkey is
// not nil). No error means that the check was successful.
func check_keys(curve Curve, pubkey *PublicKey, privkey *PrivateKey) error {
	_, err := getEC_KEY(curve, pubkey, privkey)
	return err
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
		return nil, errors.New("couldn't read key len")
	}

	key.Key = make([]byte, keyLen)
	err = binary.Read(b, binary.BigEndian, key.Key)
	if err != nil {
		return nil, errors.New("couldn't read private key")
	}

	err = key.derivePublicKey()
	if err != nil {
		return nil, errors.New("failed to derive public key: " + err.Error())
	}

	err = check_keys(key.Curve, &key.PublicKey, key)
	if err != nil {
		return nil, errors.New("key check failed: " + err.Error())
	}

	return key, nil
}

// Derive the public key from the private key, as done in:
// http://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography#Working_with_Keys
func (key *PrivateKey) derivePublicKey() error {
	// initialization
	k := C.EC_KEY_new_by_curve_name(C.int(key.Curve))
	defer C.EC_KEY_free(k)
	if key == nil {
		return errors.New("[OpenSSL] EC_KEY_new_by_curve_name FAIL")
	}

	group := C.EC_KEY_get0_group(k)
	pub_key := C.EC_POINT_new(group)
	defer C.EC_POINT_free(pub_key)

	// create BIGNUMs
	priv_key := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&key.Key[0])),
		C.int(len(key.Key)), nil)
	defer C.BN_free(priv_key)
	pub_key_x := C.BN_new()
	defer C.BN_free(pub_key_x)
	pub_key_y := C.BN_new()
	defer C.BN_free(pub_key_y)

	// the actual step which does the conversion from private to public key
	if C.EC_POINT_mul(group, pub_key, priv_key, nil, nil, nil) == C.int(0) {
		return errors.New("[OpenSSL] EC_POINT_mul FAIL")
	}
	if C.EC_KEY_set_private_key(k, priv_key) == C.int(0) {
		return errors.New("[OpenSSL] EC_KEY_set_private_key FAIL")
	}
	if C.EC_KEY_set_public_key(k, pub_key) == C.int(0) {
		return errors.New("[OpenSSL] EC_KEY_set_public_key FAIL")
	}

	// get X and Y coords from pub_key
	if C.EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_key_x,
		pub_key_y, nil) == C.int(0) {
		return errors.New("[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL")
	}

	key.PublicKey.X = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_x))
	key.PublicKey.Y = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_y))

	C.BN_bn2bin(pub_key_x, (*C.uchar)(unsafe.Pointer(&key.PublicKey.X[0])))
	C.BN_bn2bin(pub_key_y, (*C.uchar)(unsafe.Pointer(&key.PublicKey.Y[0])))
	return nil
}

// Generate a random private key for the given curve.
func GeneratePrivateKey(curve Curve) (*PrivateKey, error) {
	// initialization
	key := C.EC_KEY_new_by_curve_name(C.int(curve))
	defer C.EC_KEY_free(key)
	if key == nil {
		return nil, errors.New("[OpenSSL] EC_KEY_new_by_curve_name FAIL")
	}
	if C.EC_KEY_generate_key(key) == C.int(0) {
		return nil, errors.New("[OpenSSL] EC_KEY_generate_key FAIL")
	}
	if C.EC_KEY_check_key(key) == C.int(0) {
		return nil, errors.New("[OpenSSL] EC_KEY_check_key FAIL")
	}

	priv_key := C.EC_KEY_get0_private_key(key)
	group := C.EC_KEY_get0_group(key)
	pub_key := C.EC_KEY_get0_public_key(key)

	// create BIGNUMs
	pub_key_x := C.BN_new()
	defer C.BN_free(pub_key_x)
	pub_key_y := C.BN_new()
	defer C.BN_free(pub_key_y)

	// get X and Y coords from pub_key
	if C.EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_key_x,
		pub_key_y, nil) == C.int(0) {
		return nil, errors.New(
			"[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL")
	}

	// start transfering data back to Go
	privateKey := new(PrivateKey)
	privateKey.Curve = curve
	privateKey.Key = make([]byte, C.BN_num_bytes_not_a_macro(priv_key))
	privateKey.PublicKey.X = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_x))
	privateKey.PublicKey.Y = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_y))

	C.BN_bn2bin(priv_key, (*C.uchar)(unsafe.Pointer(&privateKey.Key[0])))
	C.BN_bn2bin(pub_key_x, (*C.uchar)(unsafe.Pointer(&privateKey.PublicKey.X[0])))
	C.BN_bn2bin(pub_key_y, (*C.uchar)(unsafe.Pointer(&privateKey.PublicKey.Y[0])))

	// do a sanity check to ensure that everything went as planned
	err := check_keys(privateKey.Curve, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, errors.New("key check failed: " + err.Error())
	}

	return privateKey, nil
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

// Generate the raw ECDH key which must be passed through an appropriate hashing
// function before being used for encryption/decryption. length was fixed at 32
// in pyelliptic. The maximum length of the shared key is dependent on the curve
// used.
func (privKey *PrivateKey) GetRawECDHKey(pubKey PublicKey, length int) ([]byte,
	error) {
	if pubKey.Curve != privKey.Curve {
		return nil, errors.New("ECC keys must be from the same curve")
	}

	other_key, err := getEC_KEY(pubKey.Curve, &pubKey, nil)
	if err != nil {
		return nil, errors.New("creating other EC_KEY failed: " + err.Error())
	}
	own_key, err := getEC_KEY(privKey.Curve, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, errors.New("creating own EC_KEY failed: " + err.Error())
	}

	C.ECDH_set_method(own_key, C.ECDH_OpenSSL())

	// compute the shared secret of the specified length
	ecdhKey := make([]byte, length)
	ecdh_keylen := int(C.ECDH_compute_key(unsafe.Pointer(&ecdhKey[0]),
		C.size_t(length), C.EC_KEY_get0_public_key(other_key), own_key, nil))

	// check if we got the length we needed
	if ecdh_keylen != length {
		return nil, errors.New(fmt.Sprintf("[OpenSSL] ECDH keylen FAIL, got"+
			" %d expected %d ", ecdh_keylen, length))
	}

	return ecdhKey, nil
}

// Sign the given data with the private key and return the signature.
func (key *PrivateKey) Sign(rawData []byte) ([]byte, error) {
	k, err := getEC_KEY(key.Curve, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// create EVP context
	md_ctx := C.EVP_MD_CTX_create()
	defer C.EVP_MD_CTX_destroy(md_ctx)

	C.EVP_MD_CTX_init(md_ctx)
	if C.EVP_DigestInit(md_ctx, C.EVP_ecdsa()) == C.int(0) {
		return nil, errors.New("[OpenSSL] EVP_DigestInit FAIL")
	}
	if C.EVP_DigestUpdate(md_ctx, unsafe.Pointer(&rawData[0]),
		C.size_t(len(rawData))) == C.int(0) {
		return nil, errors.New("[OpenSSL] EVP_DigestUpdate FAIL")
	}
	digest := make([]byte, C.EVP_MAX_MD_SIZE)
	var digest_len uint
	// get the digest
	if C.EVP_DigestFinal(md_ctx, (*C.uchar)(unsafe.Pointer(&digest[0])),
		(*C.uint)(unsafe.Pointer(&digest_len))) == C.int(0) {
		return nil, errors.New("[OpenSSL] EVP_DigestFinal FAIL")
	}

	sig_maxlen := C.ECDSA_size(k)
	sig := make([]byte, sig_maxlen)
	var sig_len uint
	// get the signature
	if C.ECDSA_sign(C.int(0), (*C.uchar)(unsafe.Pointer(&digest[0])),
		C.int(digest_len), (*C.uchar)(unsafe.Pointer(&sig[0])),
		(*C.uint)(unsafe.Pointer(&sig_len)), k) == C.int(0) {
		return nil, errors.New("[OpenSSL] ECDSA_sign FAIL")
	}

	return sig[:sig_len], nil
}

// Verify the signature for the given data and public key and return if it is
// valid or not.
func (key *PublicKey) VerifySignature(sig, rawData []byte) (bool, error) {
	k, err := getEC_KEY(key.Curve, key, nil)
	if err != nil {
		return false, err
	}

	// create EVP context
	md_ctx := C.EVP_MD_CTX_create()
	defer C.EVP_MD_CTX_destroy(md_ctx)

	C.EVP_MD_CTX_init(md_ctx)
	if C.EVP_DigestInit(md_ctx, C.EVP_ecdsa()) == C.int(0) {
		return false, errors.New("[OpenSSL] EVP_DigestInit FAIL")
	}
	if C.EVP_DigestUpdate(md_ctx, unsafe.Pointer(&rawData[0]),
		C.size_t(len(rawData))) == C.int(0) {
		return false, errors.New("[OpenSSL] EVP_DigestUpdate FAIL")
	}
	digest := make([]byte, C.EVP_MAX_MD_SIZE)
	var digest_len uint
	// get the digest
	if C.EVP_DigestFinal(md_ctx, (*C.uchar)(unsafe.Pointer(&digest[0])),
		(*C.uint)(unsafe.Pointer(&digest_len))) == C.int(0) {
		return false, errors.New("[OpenSSL] EVP_DigestFinal FAIL")
	}

	// check signature
	ret := int(C.ECDSA_verify(C.int(0), (*C.uchar)(unsafe.Pointer(&digest[0])),
		C.int(digest_len), (*C.uchar)(unsafe.Pointer(&sig[0])),
		C.int(len(sig)), k))

	switch ret {
	case -1:
		return false, errors.New("[OpenSSL] ECDSA_verify FAIL")
	case 1:
		return true, nil
	case 0:
		return false, nil
	}
	return false, errors.New("lolwut? unknown error")
}
