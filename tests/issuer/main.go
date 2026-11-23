// Command issuer is a token issuer for tests only. It signs whatever claims it
// is given with a key it generates at start-up and publishes that key as a
// JSON Web Key Set, so the gateway can verify tokens without an external
// identity provider.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
)

func main() {
	published, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	// The unpublished key signs tokens the gateway must reject.
	unpublished, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	http.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test",
			"n": b64(published.N.Bytes()), "e": b64(big.NewInt(int64(published.E)).Bytes()),
		}}})
	})
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims, err := io.ReadAll(r.Body)
		if err != nil || !json.Valid(claims) {
			http.Error(w, "claims must be JSON", http.StatusBadRequest)
			return
		}
		key := published
		if r.URL.Query().Get("key") == "unpublished" {
			key = unpublished
		}
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
		signed := b64(header) + "." + b64(claims)
		digest := sha256.Sum256([]byte(signed))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		io.WriteString(w, signed+"."+b64(signature))
	})
	log.Fatal(http.ListenAndServe(":8000", nil))
}
