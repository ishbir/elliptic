// build +cgo
package elliptic

/*
#include <openssl/obj_mac.h>
*/
import "C"

// EllipticCurve repesents the ASN.1 OID of an elliptic curve.
type EllipticCurve int

// Generated from obj_mac.h using a Python script
const (
	Secp112r1 EllipticCurve = C.NID_secp112r1
	Secp112r2 EllipticCurve = C.NID_secp112r2
	Secp128r1 EllipticCurve = C.NID_secp128r1
	Secp128r2 EllipticCurve = C.NID_secp128r2
	Secp160k1 EllipticCurve = C.NID_secp160k1
	Secp160r1 EllipticCurve = C.NID_secp160r1
	Secp160r2 EllipticCurve = C.NID_secp160r2
	Secp192k1 EllipticCurve = C.NID_secp192k1
	Secp224k1 EllipticCurve = C.NID_secp224k1
	Secp224r1 EllipticCurve = C.NID_secp224r1
	Secp256k1 EllipticCurve = C.NID_secp256k1
	Secp384r1 EllipticCurve = C.NID_secp384r1
	Secp521r1 EllipticCurve = C.NID_secp521r1
	Sect113r1 EllipticCurve = C.NID_sect113r1
	Sect113r2 EllipticCurve = C.NID_sect113r2
	Sect131r1 EllipticCurve = C.NID_sect131r1
	Sect131r2 EllipticCurve = C.NID_sect131r2
	Sect163k1 EllipticCurve = C.NID_sect163k1
	Sect163r1 EllipticCurve = C.NID_sect163r1
	Sect163r2 EllipticCurve = C.NID_sect163r2
	Sect193r1 EllipticCurve = C.NID_sect193r1
	Sect193r2 EllipticCurve = C.NID_sect193r2
	Sect233k1 EllipticCurve = C.NID_sect233k1
	Sect233r1 EllipticCurve = C.NID_sect233r1
	Sect239k1 EllipticCurve = C.NID_sect239k1
	Sect283k1 EllipticCurve = C.NID_sect283k1
	Sect283r1 EllipticCurve = C.NID_sect283r1
	Sect409k1 EllipticCurve = C.NID_sect409k1
	Sect409r1 EllipticCurve = C.NID_sect409r1
	Sect571k1 EllipticCurve = C.NID_sect571k1
	Sect571r1 EllipticCurve = C.NID_sect571r1
)
