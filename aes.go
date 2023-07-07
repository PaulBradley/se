package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"go.riyazali.net/sqlite"
)

type aes_encrypt struct{}
type aes_decrypt struct{}
type generate_aes256_key struct{}

func (input *aes_encrypt) Args() int           { return 1 }
func (input *aes_encrypt) Deterministic() bool { return true }
func (input *aes_encrypt) Apply(ctx *sqlite.Context, values ...sqlite.Value) {
	var err error
	var keyString string

	keyString, err = retrieveEnvironmentVariable()
	if err != nil {
		ctx.ResultError(err)
		return
	}

	// since the key is in string,
	// we need to convert it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(values[0].Text())

	// create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		ctx.ResultError(err)
		return
	}

	// create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	// https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		ctx.ResultError(err)
		return
	}

	// create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		ctx.ResultError(err)
		return
	}

	// encrypt the data using aesGCM.Seal
	// since we don't want to save the nonce
	// somewhere else in this case, we add it
	// as a prefix to the encrypted data.
	// The first nonce argument in Seal is the prefix.
	encrypted_text := aesGCM.Seal(nonce, nonce, plaintext, nil)

	ctx.ResultBlob(encrypted_text)
}

func (input *aes_decrypt) Args() int           { return 1 }
func (input *aes_decrypt) Deterministic() bool { return true }
func (input *aes_decrypt) Apply(ctx *sqlite.Context, values ...sqlite.Value) {
	var err error
	var keyString string

	keyString, err = retrieveEnvironmentVariable()
	if err != nil {
		ctx.ResultError(err)
		return
	}

	key, _ := hex.DecodeString(keyString)
	encrypted_text := []byte(values[0].Text())

	block, err := aes.NewCipher(key)
	if err != nil {
		ctx.ResultError(err)
		return
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		ctx.ResultError(err)
		return
	}

	nonceSize := aesGCM.NonceSize()

	nonce, cipherText := encrypted_text[:nonceSize], encrypted_text[nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		ctx.ResultError(err)
		return
	}

	ctx.ResultText(string(plainText))
}

func (input *generate_aes256_key) Args() int           { return 0 }
func (input *generate_aes256_key) Deterministic() bool { return true }
func (input *generate_aes256_key) Apply(ctx *sqlite.Context, values ...sqlite.Value) {

	// generate a random 32 byte key for AES-256
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		ctx.ResultError(err)
		return
	}

	// encode key in bytes to string
	// and keep as secret, put in a vault
	ctx.ResultText(hex.EncodeToString(bytes))
}

func retrieveEnvironmentVariable() (key string, err error) {
	keyString := os.Getenv("SIGNALZERO_SQLITE_AES")

	if len(keyString) == 0 {
		return "", errors.New("Environment variable not defined : SIGNALZERO_SQLITE_AES")
	}

	return keyString, nil
}
