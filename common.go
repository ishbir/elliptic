package elliptic

// OpenSSLError represents an error encountered while running an OpenSSL function.
type OpenSSLError struct {
	Function string
}

func (err OpenSSLError) Error() string {
	return "[OpenSSL] " + err.Function + " FAILED. " + errorFromErrorQueue().Error()
}
