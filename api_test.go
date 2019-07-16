package curve25519

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSharedSecret(t *testing.T) {
	for i := 0; i < 10000; i++ {
		private1 := GenerateKey()
		public1 := private1.Public()
		require.True(t, public1.isCanonical())

		private2 := GenerateKey()
		public2 := private2.Public()
		require.True(t, public2.isCanonical())

		secret1 := private1.SharedSecret(public2)
		secret2 := private2.SharedSecret(public1)

		require.Equal(t, secret1, secret2)
	}
}

func TestSignature(t *testing.T) {
	file, err := os.Open(filepath.Join("testdata", "signature.txt"))
	require.NoError(t, err)
	defer file.Close()

	for {
		var hexPrivateKey, hexMessage, hexSignature string
		n, err := fmt.Fscanln(file, &hexPrivateKey, &hexMessage, &hexSignature)
		if n == 0 && err == io.EOF {
			break
		}
		require.NoError(t, err)

		bytes, err := hex.DecodeString(hexPrivateKey)
		require.NoError(t, err)
		privateKey := NewPrivateKey(bytes)

		message, err := hex.DecodeString(hexMessage)
		require.NoError(t, err)
		actual := privateKey.Sign(message)
		require.True(t, actual.isCanonical())

		bytes, err = hex.DecodeString(hexSignature)
		require.NoError(t, err)
		expected := NewSignature(bytes)

		require.Equal(t, expected, actual)

		result := Verify(message, actual, privateKey.Public(), true)
		require.True(t, result)
	}
}

func TestMine(t *testing.T) {
	for i := 0; i < 1000; i++ {
		privateKey := GenerateKey()
		publicKey := privateKey.Public()
		tempPublicKey := privateKey.myPublic()
		require.Equal(t, tempPublicKey, publicKey)

		privateKey2 := GenerateKey()
		publicKey2 := privateKey2.Public()
		tempPublicKey = privateKey2.myPublic()
		require.Equal(t, tempPublicKey, publicKey2)

		sharedSecret := privateKey.SharedSecret(publicKey2)
		sharedSecret2 := privateKey.mySharedSecret(publicKey2)
		require.Equal(t, sharedSecret, sharedSecret2)
	}
}

func BenchmarkMine(b *testing.B) {
	testPublic := func(f func(sk *PrivateKey)) func(b *testing.B) {
		return func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				b.StopTimer()
				privateKey := GenerateKey()
				b.StartTimer()
				f(privateKey)
			}
		}
	}

	b.Run("goPublic", testPublic(func(sk *PrivateKey) {
		sk.Public()
	}))

	b.Run("myPublic", testPublic(func(sk *PrivateKey) {
		sk.myPublic()
	}))

	testSharedSecret := func(f func(sk *PrivateKey, pk *PublicKey)) func(b *testing.B) {
		return func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				b.StopTimer()
				privateKey := GenerateKey()
				publicKey := GenerateKey().Public()
				b.StartTimer()
				f(privateKey, publicKey)
			}
		}
	}

	b.Run("goSharedSecret", testSharedSecret(func(sk *PrivateKey, pk *PublicKey) {
		sk.SharedSecret(pk)
	}))

	b.Run("mySharedSecret", testSharedSecret(func(sk *PrivateKey, pk *PublicKey) {
		sk.mySharedSecret(pk)
	}))
}
