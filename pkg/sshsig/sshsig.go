// Package sshsig signs messages in OpenSSH's signature format
// (PROTOCOL.sshsig), the format `ssh-keygen -Y sign` writes and
// `ssh-keygen -Y verify` checks, with an Ed25519 key.
package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	magic   = "SSHSIG"
	keyType = "ssh-ed25519"
	hashAlg = "sha512"
)

// Signer signs messages for one namespace.
type Signer struct {
	key       ed25519.PrivateKey
	namespace string
}

// New returns a Signer. The namespace keeps signatures made for one purpose
// from verifying for another; verifiers pass the same value to -n.
func New(key ed25519.PrivateKey, namespace string) *Signer {
	return &Signer{key: key, namespace: namespace}
}

func putString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // keys, namespaces and hashes are far below 4 GiB
	return append(b, s...)
}

func readString(b []byte) (s, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("truncated key")
	}
	n := binary.BigEndian.Uint32(b)
	if int64(n) > int64(len(b)-4) {
		return nil, nil, errors.New("truncated key")
	}
	return b[4 : 4+n], b[4+n:], nil
}

// ParsePrivateKey reads an unencrypted OpenSSH private key file holding one
// Ed25519 key, as `ssh-keygen -t ed25519 -N ""` writes it.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil, errors.New("not an OpenSSH private key")
	}
	const header = "openssh-key-v1\x00"
	b, ok := bytes.CutPrefix(block.Bytes, []byte(header))
	if !ok {
		return nil, errors.New("not an openssh-key-v1 key")
	}
	var cipher, kdf, private []byte
	var err error
	if cipher, b, err = readString(b); err != nil {
		return nil, err
	}
	if kdf, b, err = readString(b); err != nil {
		return nil, err
	}
	if string(cipher) != "none" || string(kdf) != "none" {
		return nil, errors.New("the key is encrypted; give it an empty passphrase")
	}
	if _, b, err = readString(b); err != nil { // kdf options
		return nil, err
	}
	if len(b) < 4 || binary.BigEndian.Uint32(b) != 1 {
		return nil, errors.New("the file must hold exactly one key")
	}
	if _, b, err = readString(b[4:]); err != nil { // public key
		return nil, err
	}
	if private, _, err = readString(b); err != nil {
		return nil, err
	}
	if len(private) < 8 || !bytes.Equal(private[:4], private[4:8]) {
		return nil, errors.New("corrupt key: check values differ")
	}
	p := private[8:]
	var typ, pub, sk []byte
	if typ, p, err = readString(p); err != nil {
		return nil, err
	}
	if string(typ) != keyType {
		return nil, fmt.Errorf("key type %s, want %s", typ, keyType)
	}
	if pub, p, err = readString(p); err != nil {
		return nil, err
	}
	if sk, _, err = readString(p); err != nil {
		return nil, err
	}
	// The stored public half must be the seed's: signing with a mismatched
	// pair gives signatures nobody can verify, and signing one message under
	// two public keys with the same seed leaks the private key.
	if len(sk) != ed25519.PrivateKeySize || !bytes.Equal(sk[ed25519.SeedSize:], pub) ||
		!bytes.Equal(ed25519.NewKeyFromSeed(sk[:ed25519.SeedSize]), sk) {
		return nil, errors.New("corrupt Ed25519 key")
	}
	return ed25519.PrivateKey(sk), nil
}

func (s *Signer) publicBlob() []byte {
	b := putString(nil, []byte(keyType))
	return putString(b, s.key[ed25519.SeedSize:])
}

// PublicKey returns the public key as an authorized_keys line without a
// comment, such as "ssh-ed25519 AAAA...".
func (s *Signer) PublicKey() string {
	return keyType + " " + base64.StdEncoding.EncodeToString(s.publicBlob())
}

// Sign returns the armored signature of message.
func (s *Signer) Sign(message []byte) string {
	h := sha512.Sum512(message)
	signed := []byte(magic)
	signed = putString(signed, []byte(s.namespace))
	signed = putString(signed, nil) // reserved
	signed = putString(signed, []byte(hashAlg))
	signed = putString(signed, h[:])

	sig := putString(nil, []byte(keyType))
	sig = putString(sig, ed25519.Sign(s.key, signed))

	blob := []byte(magic)
	blob = binary.BigEndian.AppendUint32(blob, 1)
	blob = putString(blob, s.publicBlob())
	blob = putString(blob, []byte(s.namespace))
	blob = putString(blob, nil)
	blob = putString(blob, []byte(hashAlg))
	blob = putString(blob, sig)

	enc := base64.StdEncoding.EncodeToString(blob)
	var out strings.Builder
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70])
		out.WriteByte('\n')
		enc = enc[70:]
	}
	out.WriteString(enc)
	out.WriteString("\n-----END SSH SIGNATURE-----\n")
	return out.String()
}
