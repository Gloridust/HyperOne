package auth

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SessionKeys holds the directional AEAD keys for one HyperOne session. Each
// direction gets an independent key so a reflection of ciphertext can never be
// decrypted in the other direction.
type SessionKeys struct {
	ClientToServer []byte // 32 bytes, ChaCha20-Poly1305 key
	ServerToClient []byte
}

// DeriveKeys turns the pre-shared key and the two handshake randoms that both
// peers observed (clientRandom from the ClientHello, serverRandom from the
// ServerHello relayed back) into directional AEAD keys. Binding to both randoms
// means every session's keys differ even under a fixed PSK, and a peer that did
// not see the real handshake cannot derive them.
func DeriveKeys(psk, clientRandom, serverRandom []byte) (SessionKeys, error) {
	salt := make([]byte, 0, len(clientRandom)+len(serverRandom))
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)

	r := hkdf.New(sha256.New, psk, salt, []byte("hyperone/v1 inner keys"))
	ks := SessionKeys{
		ClientToServer: make([]byte, 32),
		ServerToClient: make([]byte, 32),
	}
	if _, err := io.ReadFull(r, ks.ClientToServer); err != nil {
		return SessionKeys{}, err
	}
	if _, err := io.ReadFull(r, ks.ServerToClient); err != nil {
		return SessionKeys{}, err
	}
	return ks, nil
}
