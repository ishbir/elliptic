package elliptic

// +build cgo

// #cgo pkg-config: libcrypto
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN
import "C"
