package wallet

import (
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	knownPrivBytes            = []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32}
	knownPrivKey, knownPubKey = ec.PrivateKeyFromBytes(knownPrivBytes)
	knownPrivKeyHex           = hex.EncodeToString(knownPrivBytes)
	knownWIF                  = WIF(knownPrivKey.Wif())
)

// TestToPrivateKey tests the ToPrivateKey function
func TestToPrivateKey(t *testing.T) {
	t.Run("string hex input", func(t *testing.T) {
		privKey, err := ToPrivateKey(knownPrivKeyHex)
		require.NoError(t, err)
		require.NotNil(t, privKey)

		// Verify the private key is correct
		assert.Equal(t, knownPrivKey.Serialize(), privKey.Serialize())
	})

	t.Run("WIF input", func(t *testing.T) {
		privKey, err := ToPrivateKey(knownWIF)
		require.NoError(t, err)
		require.NotNil(t, privKey)

		// Verify the private key is correct
		assert.Equal(t, knownPrivKey.Serialize(), privKey.Serialize())
	})

	t.Run("*ec.PrivateKey input", func(t *testing.T) {
		privKey, err := ToPrivateKey(knownPrivKey)
		require.NoError(t, err)
		require.NotNil(t, privKey)

		// Verify it's the same private key
		assert.Equal(t, knownPrivKey, privKey)
	})

	t.Run("nil *ec.PrivateKey input", func(t *testing.T) {
		var nilPrivKey *ec.PrivateKey = nil
		privKey, err := ToPrivateKey(nilPrivKey)
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid hex string", func(t *testing.T) {
		privKey, err := ToPrivateKey("not a valid hex string")
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "failed to parse private key from string hex")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		privKey, err := ToPrivateKey(WIF("invalid wif"))
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "failed to parse private key from string containing WIF")
	})
}

// TestToKeyDeriver tests the ToKeyDeriver function
func TestToKeyDeriver(t *testing.T) {
	// Create a known private key for testing
	knownKeyDeriver := NewKeyDeriver(knownPrivKey)

	t.Run("string hex input", func(t *testing.T) {
		keyDeriver, err := ToKeyDeriver(knownPrivKeyHex)
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)

		// Verify the key deriver has the correct identity key
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("WIF input", func(t *testing.T) {
		keyDeriver, err := ToKeyDeriver(knownWIF)
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)

		// Verify the key deriver has the correct identity key
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("*ec.PrivateKey input", func(t *testing.T) {
		keyDeriver, err := ToKeyDeriver(knownPrivKey)
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)

		// Verify the key deriver has the correct identity key
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("*KeyDeriver input", func(t *testing.T) {
		keyDeriver, err := ToKeyDeriver(knownKeyDeriver)
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)

		// Verify it's the same key deriver
		assert.Equal(t, knownKeyDeriver, keyDeriver)
	})

	t.Run("nil *ec.PrivateKey input", func(t *testing.T) {
		var nilPrivKey *ec.PrivateKey = nil
		keyDeriver, err := ToKeyDeriver(nilPrivKey)
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("nil *KeyDeriver input", func(t *testing.T) {
		var nilKeyDeriver *KeyDeriver = nil
		keyDeriver, err := ToKeyDeriver(nilKeyDeriver)
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid hex string", func(t *testing.T) {
		keyDeriver, err := ToKeyDeriver("not a valid hex string")
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "failed to parse private key from string hex")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		keyDeriver, err := ToKeyDeriver(WIF("invalid wif"))
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "failed to parse private key from string containing WIF")
	})
}

// TestToIdentityKey tests the ToIdentityKey function
func TestToIdentityKey(t *testing.T) {
	// Create a known private key for testing
	knownPubKeyHex := knownPubKey.ToDERHex()
	knownKeyDeriver := NewKeyDeriver(knownPrivKey)

	t.Run("string input", func(t *testing.T) {
		pubKey, err := ToIdentityKey(knownPubKeyHex)
		require.NoError(t, err)
		require.NotNil(t, pubKey)

		// Verify the public key is correct
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("WIF input", func(t *testing.T) {
		pubKey, err := ToIdentityKey(knownWIF)
		require.NoError(t, err)
		require.NotNil(t, pubKey)

		// Verify the public key is correct
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("*KeyDeriver input", func(t *testing.T) {
		pubKey, err := ToIdentityKey(knownKeyDeriver)
		require.NoError(t, err)
		require.NotNil(t, pubKey)

		// Verify the public key is correct
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("*ec.PublicKey input", func(t *testing.T) {
		pubKey, err := ToIdentityKey(knownPubKey)
		require.NoError(t, err)
		require.NotNil(t, pubKey)

		// Verify it's the same public key
		assert.Equal(t, knownPubKey, pubKey)
	})

	t.Run("nil *KeyDeriver input", func(t *testing.T) {
		var nilKeyDeriver *KeyDeriver = nil
		pubKey, err := ToIdentityKey(nilKeyDeriver)
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "key deriver cannot be nil")
	})

	t.Run("nil *ec.PublicKey input", func(t *testing.T) {
		var nilPubKey *ec.PublicKey = nil
		pubKey, err := ToIdentityKey(nilPubKey)
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "public key cannot be nil")
	})

	t.Run("invalid string", func(t *testing.T) {
		pubKey, err := ToIdentityKey("not a valid public key string")
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to parse public key from string")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		pubKey, err := ToIdentityKey(WIF("invalid wif"))
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to parse public key from string containing WIF")
	})
}
