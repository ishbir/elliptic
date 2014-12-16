// +build windows cgo

package elliptic

/*

#cgo pkg-config: libcrypto

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <errno.h>
#include <openssl/crypto.h>
#include <windows.h>

CRITICAL_SECTION* goopenssl_locks;

int Goopenssl_init_locks() {
	int rc = 0;
	int nlock;
	int i;
	int locks_needed = CRYPTO_num_locks();

	goopenssl_locks = (CRITICAL_SECTION*)malloc(
		sizeof(*goopenssl_locks) * locks_needed);
	if (!goopenssl_locks) {
		return ENOMEM;
	}
	for (nlock = 0; nlock < locks_needed; ++nlock) {
		InitializeCriticalSection(&goopenssl_locks[nlock]);
	}

	return 0;
}

void Goopenssl_thread_locking_callback(int mode, int n, const char *file,
	int line) {
	if (mode & CRYPTO_LOCK) {
		EnterCriticalSection(&goopenssl_locks[n]);
	} else {
		LeaveCriticalSection(&goopenssl_locks[n]);
	}
}
*/
import "C"
