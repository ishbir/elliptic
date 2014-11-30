// Copyright (C) 2014 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build cgo

package elliptic

/*
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

extern int Goopenssl_init_locks();
extern void Goopenssl_thread_locking_callback(int, int, const char*, int);

static int Goopenssl_init_threadsafety() {
	// Set up OPENSSL thread safety callbacks.  We only set the locking
	// callback because the default id callback implementation is good
	// enough for us.
	int rc = Goopenssl_init_locks();
	if (rc == 0) {
		CRYPTO_set_locking_callback(Goopenssl_thread_locking_callback);
	}
	return rc;
}

static void OpenSSL_add_all_algorithms_not_a_macro() {
	OpenSSL_add_all_algorithms();
}

*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
)

func init() {
	C.OPENSSL_config(nil)
	C.ENGINE_load_builtin_engines()
	C.ERR_load_crypto_strings()
	C.OpenSSL_add_all_algorithms_not_a_macro()
	rc := C.Goopenssl_init_threadsafety()
	if rc != 0 {
		panic(fmt.Errorf("Goopenssl_init_locks failed with %d", rc))
	}
}

func Cleanup() {
	// Removes all digests and ciphers
	C.EVP_cleanup()

	// if you omit the next, a small leak may be left when you make use of the
	// BIO (low level API) for e.g. base64 transformations
	C.CRYPTO_cleanup_all_ex_data()

	// Remove error strings
	C.ERR_free_strings()
}

// errorFromErrorQueue needs to run in the same OS thread as the operation
// that caused the possible error
func errorFromErrorQueue() error {
	var errs []string
	for {
		err := C.ERR_get_error()
		if err == 0 {
			break
		}
		errs = append(errs, fmt.Sprintf("%s:%s:%s",
			C.GoString(C.ERR_lib_error_string(err)),
			C.GoString(C.ERR_func_error_string(err)),
			C.GoString(C.ERR_reason_error_string(err))))
	}
	return errors.New(fmt.Sprintf("OpenSSL errors: %s", strings.Join(errs, "\n")))
}
