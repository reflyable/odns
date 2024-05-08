package vpn_send

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/hkdf"

	"crypto/sha256"
	"io"
)

func encryptSymmetric(in, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipher := cipher.NewCTR(block, iv)

	out := make([]byte, len(in))
	cipher.XORKeyStream(out, in)

	return out, nil
}

// Encrypt is a function for encryption
func Encrypt(public *ecdsa.PublicKey, in, s1, s2 []byte) ([]byte, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	prv, err := private.ECDH()
	if err != nil {
		return nil, err
	}
	pub, err := public.ECDH()
	if err != nil {
		return nil, err
	}
	shared, err := prv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	_, err = io.ReadFull(hkdf.New(sha256.New, shared, s1, s2), key)
	if err != nil {
		return nil, err
	}
	out, err := encryptSymmetric(in, key[:16], key[16:])
	if err != nil {
		return nil, err
	}
	pubCompress := elliptic.MarshalCompressed(private.Curve, private.PublicKey.X, private.PublicKey.Y)
	size := len(pubCompress) + len(out)
	o := make([]byte, size)
	copy(o[:len(pubCompress)], pubCompress)
	copy(o[len(pubCompress):], out)
	return o, nil

}
func Decrypt(private *ecdsa.PrivateKey, in, s1, s2 []byte) ([]byte, error) {
	messageStart := (private.PublicKey.Curve.Params().BitSize+7)/8 + 1
	public := new(ecdsa.PublicKey)
	public.Curve = private.PublicKey.Curve
	public.X, public.Y = elliptic.UnmarshalCompressed(public.Curve, in[:messageStart])
	if public.X == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	prv, err := private.ECDH()
	if err != nil {
		return nil, err
	}
	pub, err := public.ECDH()
	if err != nil {
		return nil, err
	}
	shared, err := prv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	_, err = io.ReadFull(hkdf.New(sha256.New, shared, s1, s2), key)
	if err != nil {
		return nil, err
	}
	out, err := encryptSymmetric(in[messageStart:], key[:16], key[16:])
	if err != nil {
		return nil, err
	}
	return out, nil

}
