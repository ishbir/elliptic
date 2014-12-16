// +build linux darwin cgo
// +build !windows

package elliptic

/*
#include <errno.h>
#include <openssl/crypto.h>
#include <pthread.h>

pthread_mutex_t* goopenssl_locks;

int Goopenssl_init_locks() {
	int rc = 0;
	int nlock;
	int i;
	int locks_needed = CRYPTO_num_locks();

	goopenssl_locks = (pthread_mutex_t*)malloc(
		sizeof(pthread_mutex_t) * locks_needed);
	if (!goopenssl_locks) {
		return ENOMEM;
	}
	for (nlock = 0; nlock < locks_needed; ++nlock) {
		rc = pthread_mutex_init(&goopenssl_locks[nlock], NULL);
		if (rc != 0) {
			break;
		}
	}

	if (rc != 0) {
		for (i = nlock - 1; i >= 0; --i) {
			pthread_mutex_destroy(&goopenssl_locks[i]);
		}
		free(goopenssl_locks);
		goopenssl_locks = NULL;
	}
	return rc;
}

void Goopenssl_thread_locking_callback(int mode, int n, const char *file,
	int line) {
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&goopenssl_locks[n]);
	} else {
		pthread_mutex_unlock(&goopenssl_locks[n]);
	}
}
*/
import "C"
