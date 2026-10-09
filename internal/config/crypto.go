package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

var ErrWrongPassword = errors.New("wrong master password")

// kdfParams are stored in the file so they can be raised later without breaking old files.
type kdfParams struct {
	KDF     string `json:"kdf"`
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB
	Threads uint8  `json:"threads"`
}

// envelope is the on-disk format: the whole host list sealed with AES-256-GCM.
type envelope struct {
	Version int `json:"version"`
	kdfParams
	Nonce []byte `json:"nonce"`
	Data  []byte `json:"data"`
}

func newKDFParams() (kdfParams, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return kdfParams{}, err
	}
	return kdfParams{KDF: "argon2id", Salt: salt, Time: 3, Memory: 64 * 1024, Threads: 4}, nil
}

func (p kdfParams) deriveKey(master []byte) ([]byte, error) {
	if p.KDF != "argon2id" || len(p.Salt) == 0 || p.Time == 0 || p.Memory == 0 || p.Threads == 0 {
		return nil, errors.New("unsupported or corrupt key derivation settings")
	}
	return argon2.IDKey(master, p.Salt, p.Time, p.Memory, p.Threads, 32), nil
}

func seal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func unseal(key, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("corrupt hosts file: bad nonce")
	}
	out, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newKey(master []byte) (kdfParams, []byte, error) {
	p, err := newKDFParams()
	if err != nil {
		return p, nil, err
	}
	key, err := p.deriveKey(master)
	return p, key, err
}
