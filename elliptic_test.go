package elliptic

import (
	"reflect"
	"testing"
)

var curveList = []Curve{
	Secp112r1, Secp112r2, Secp128r1, Secp128r2, Secp160k1, Secp160r1,
	Secp160r2, Secp192k1, Secp224k1, Secp224r1, Secp256k1, Secp384r1,
	Secp521r1, Sect113r1, Sect113r2, Sect131r1, Sect131r2, Sect163k1, Sect163r1,
	Sect163r2, Sect193r1, Sect193r2, Sect233k1, Sect233r1, Sect239k1, Sect283k1,
	Sect283r1, Sect409k1, Sect409r1, Sect571k1, Sect571r1,
}

func TestGeneratePrivateKey(t *testing.T) {
	for _, curve := range curveList {
		_, err := GeneratePrivateKey(curve)
		if err != nil {
			t.Error("private key generation with", int(curve), "curve failed")
		}
	}
}

func TestPrivateKeySerialization(t *testing.T) {
	key, err := GeneratePrivateKey(Sect409r1)

	if err != nil {
		t.Fatal("private key generation failed:", err)
	}
	raw := key.Serialize()
	key1, err := PrivateKeyFromBytes(raw)
	if err != nil {
		t.Fatal("deserialization failed:", err)
	}
	if !reflect.DeepEqual(key.Key, key1.Key) {
		t.Fatal("deserialized key not same as original")
	}
	if !reflect.DeepEqual(key.PublicKey, key1.PublicKey) {
		t.Fatal("deserialized public key not same as original")
	}
}

func TestPublicKeySerialization(t *testing.T) {
	key, err := GeneratePrivateKey(Secp224k1)
	if err != nil {
		t.Fatal("private key generation failed:", err)
	}

	raw := key.PublicKey.Serialize()
	key1, err := PublicKeyFromBytes(raw)
	if err != nil {
		t.Fatal("deserialization failed:", err)
	}
	if !reflect.DeepEqual(key.PublicKey, *key1) {
		t.Fatal("deserialized key not same as original")
	}
}

func TestGetRawECDHKey(t *testing.T) {
	key1, err := GeneratePrivateKey(Secp384r1)
	if err != nil {
		t.Fatal("private key 1 generation failed:", err)
	}
	key2, err := GeneratePrivateKey(Secp384r1)
	if err != nil {
		t.Fatal("private key 2 generation failed:", err)
	}
	failKey, err := GeneratePrivateKey(Secp224k1)
	if err != nil {
		t.Fatal("private key fail generation failed:", err)
	}
	_, err = key1.GetRawECDHKey(failKey.PublicKey, 32)
	if err != nil && err.Error() != "ECC keys must be from the same curve" {
		t.Error("ECDH key generation succeeded with different curves")
	}
	sharedKey1, err := key1.GetRawECDHKey(key2.PublicKey, 48)
	if err != nil {
		t.Fatal("ECDH key generation failed:", err)
	}
	sharedKey2, err := key2.GetRawECDHKey(key1.PublicKey, 48)
	if err != nil {
		t.Fatal("ECDH key generation failed:", err)
	}
	if !reflect.DeepEqual(sharedKey1, sharedKey2) {
		t.Fatal("generated shared keys not the same!")
	}
}