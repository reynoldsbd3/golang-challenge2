package secnet

import (
	"crypto/rand"
	"golang.org/x/crypto/nacl/box"
	"io"
	"net"
)

func Dial(addr string) (io.ReadWriteCloser, error) {

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	// TODO: set a timeout

	// Handshake/kex
	var peerPub *[32]byte
	conn.Write((*pub)[:])
	conn.Read((*peerPub)[:])

	return SecureConnection{conn, NewSecureReader(conn, priv, peerPub), NewSecureWriter(conn, priv, peerPub)}, nil
}

type SecureConnection struct {
	conn net.Conn
	sr   io.Reader
	sw   io.Writer
}

func (sc SecureConnection) Close() error {
	return sc.conn.Close()
}

func (sc SecureConnection) Read(p []byte) (n int, err error) {
	return sc.sr.Read(p)
}

func (sc SecureConnection) Write(p []byte) (n int, err error) {
	return sc.sw.Write(p)
}

type SecureReader struct {
	key   *[32]byte
	r     io.Reader
	nonce [24]byte
}

func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {

	var key [32]byte
	box.Precompute(&key, pub, priv)
	return SecureReader{key: &key, r: r}
}

func (sr SecureReader) Read(p []byte) (n int, err error) {

	// Get the ciphertext
	var in []byte
	n, err = sr.r.Read(in)
	if err != nil {
		return 0, err
	}

	// Do decryption
	var msg []byte
	box.OpenAfterPrecomputation(msg, in, &sr.nonce, sr.key)

	// Save the new nonce for use in the next read
	copy(sr.nonce[:], msg[:24])

	// Now return the plaintext
	copy(p, msg[24:])
	return len(p), nil
}

type SecureWriter struct {
	key   *[32]byte
	w     io.Writer
	nonce [24]byte
}

func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {

	var key [32]byte
	box.Precompute(&key, pub, priv)
	return SecureWriter{key: &key, w: w}
}

func (sw SecureWriter) Write(p []byte) (n int, err error) {

	// Generate the nonce for the next write and send it along with the
	// plaintext for this write
	var nextNonce [24]byte
	rand.Read(nextNonce[:])
	msg := append(nextNonce[:], p...)

	// Do the encryption
	var out []byte
	box.SealAfterPrecomputation(out, msg, &sw.nonce, sw.key)

	// Save the new nonce for use in the next write
	sw.nonce = nextNonce

	// Then send the ciphertext on its way
	return sw.w.Write(out)
}
