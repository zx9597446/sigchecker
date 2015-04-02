// Package sigchecker provides ...
package sigchecker

import (
	"crypto/md5"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ant0ine/go-json-rest/rest"
)

// SignatureChecker verifies the request header signature
// it returns http.StatusUnauthorized if failed check
type SignatureChecker struct {
	HeaderKey string
	Secret    string
}

// MiddlewareFunc makes SignatureChecker implement the Middleware interface.
func (mw *SignatureChecker) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {
	if mw.HeaderKey == "" {
		log.Fatal("HeaderKey is required for SignatureChecker")
	}
	return func(w rest.ResponseWriter, r *rest.Request) {
		if !checkSignature(r.Header.Get(mw.HeaderKey), mw.Secret) {
			rest.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// call the wrapped handler
		handler(w, r)
	}
}

func checkSignature(sig, key string) bool {
	arr := strings.Split(sig, ",")
	if len(arr) != 2 {
		return false
	}
	timestamp := arr[0]
	sigClt := arr[1]
	sigSvr := fmt.Sprintf("%x", md5.Sum([]byte(timestamp+key)))
	return sigClt == sigSvr
}

// helper function to make new SignatureChecker
func NewSignatureChecker(headerKey, secret string) *SignatureChecker {
	return &SignatureChecker{headerKey, secret}
}
