package crypto

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/ed25519"
	amino "github.com/tendermint/go-amino"
)

func TestSignAndValidateEd25519(t *testing.T) {

	privKey := GenPrivKeyEd25519()
	pubKey := privKey.PubKey()

	msg := CRandBytes(128)
	sig := privKey.Sign(msg)

	// Test the signature
	assert.True(t, pubKey.VerifyBytes(msg, sig))

	// Mutate the signature, just one bit.
	sigEd := sig.(SignatureEd25519)
	sigEd[7] ^= byte(0x01)
	sig = sigEd

	assert.False(t, pubKey.VerifyBytes(msg, sig))
}

func TestSignAndValidateSecp256k1(t *testing.T) {
	privKey := GenPrivKeySecp256k1()
	pubKey := privKey.PubKey()

	msg := CRandBytes(128)
	sig := privKey.Sign(msg)

	assert.True(t, pubKey.VerifyBytes(msg, sig))

	// Mutate the signature, just one bit.
	sigEd := sig.(SignatureSecp256k1)
	sigEd[3] ^= byte(0x01)
	sig = sigEd

	assert.False(t, pubKey.VerifyBytes(msg, sig))
}

func TestSignatureEncodings(t *testing.T) {
	cases := []struct {
		privKey   PrivKey
		sigSize   int
		sigPrefix amino.PrefixBytes
	}{
		{
			privKey:   GenPrivKeyEd25519(),
			sigSize:   ed25519.SignatureSize,
			sigPrefix: [4]byte{0x3d, 0xa1, 0xdb, 0x2a},
		},
		{
			privKey:   GenPrivKeySecp256k1(),
			sigSize:   0, // unknown
			sigPrefix: [4]byte{0x16, 0xe1, 0xfe, 0xea},
		},
	}

	for _, tc := range cases {
		// note we embed them from the beginning....
		pubKey := tc.privKey.PubKey()

		msg := CRandBytes(128)
		sig := tc.privKey.Sign(msg)

		// store as amino
		bin, err := cdc.MarshalBinaryBare(sig)
		require.Nil(t, err, "%+v", err)
		if tc.sigSize != 0 {
			// Q: where is 1 byte coming from?
			assert.Equal(t, tc.sigSize+amino.PrefixBytesLen+1, len(bin))
		}
		assert.Equal(t, tc.sigPrefix[:], bin[0:amino.PrefixBytesLen])

		// and back
		sig2 := Signature(nil)
		err = cdc.UnmarshalBinaryBare(bin, &sig2)
		require.Nil(t, err, "%+v", err)
		assert.EqualValues(t, sig, sig2)
		assert.True(t, pubKey.VerifyBytes(msg, sig2))

		/*
			// store as json
			js, err := data.ToJSON(sig)
			require.Nil(t, err, "%+v", err)
			assert.True(t, strings.Contains(string(js), tc.sigName))

			// and back
			sig3 := Signature{}
			err = data.FromJSON(js, &sig3)
			require.Nil(t, err, "%+v", err)
			assert.EqualValues(t, sig, sig3)
			assert.True(t, pubKey.VerifyBytes(msg, sig3))

			// and make sure we can textify it
			text, err := data.ToText(sig)
			require.Nil(t, err, "%+v", err)
			assert.True(t, strings.HasPrefix(text, tc.sigName))
		*/
	}
}
func TestSignatureSerializationBLS381KOS(t *testing.T) {
	for i := 0; i < 100; i++ {
		priv := GenPrivKeyBLS381KOS()
		pub := priv.PubKey()
		pubKos := pub.(PubKeyBLS381KOS)
		msg := CRandBytes(128)
		sig := priv.Sign(msg)
		sigdes, err := SignatureFromBytes(sig.Bytes())
		require.Nil(t, err, "BLS381KOS signature from bytes error %s", err)
		require.True(t, sig.Equals(sigdes), "BLS381KOS signature serialization failure")
		pbkds, err := PubKeyFromBytes(pubKos.Bytes())
		require.Nil(t, err, "BLS381KOS pubkey from bytes error %s", err)
		require.True(t, pubKos.Equals(pbkds), "BLS381KOS pubkey serialization failure")
	}
}
func TestSignAndValidateBLS381KOS(t *testing.T) {
	for i := 0; i < 1000; i++ {
		priv := GenPrivKeyBLS381KOS()
		pub := priv.PubKey()
		pubKos := pub.(PubKeyBLS381KOS)
		msg := CRandBytes(128)
		sig := priv.Sign(msg)
		require.True(t, pubKos.VerifyBytes(msg, sig), "BLS381KOS failed single signature test")
	}
}

func TestSignAndValidateMultiSignatureBLS381KOS(t *testing.T) {
	NUMSIGNERS := 10
	NUMTESTS := 5
	for i := 0; i < NUMTESTS; i++ {
		privs := make([]PrivKeyBLS381KOS, NUMSIGNERS)
		pubs := make([]PubKey, NUMSIGNERS)
		sigs := make([]AggregatableSignature, NUMSIGNERS)
		multi := make([]int64, NUMSIGNERS)
		msg := CRandBytes(128)
		for j := 0; j < NUMSIGNERS; j++ {
			privs[j] = GenPrivKeyBLS381KOS()
			pubs[j] = privs[j].PubKey()
			sig := privs[j].Sign(msg)
			sigs[j] = sig.(AggregatableSignature)
			multi[j] = 1
		}
		var sg SignatureBLS381KOS
		sga, ok := sg.Aggregate(sigs)
		sg = sga.(SignatureBLS381KOS)
		require.True(t, ok, "BLS381KOS signature aggregation failure")
		require.True(t, sg.VerifyBytesWithMultiplicity(pubs, multi, msg), "BLS381KOS multisignature verification failed")
	}
}

func TestSignAndValidateMultiplicitySignatureBLS381KOS(t *testing.T) {
	NUMSIGNERS := 10
	NUMTESTS := 5
	for i := 0; i < NUMTESTS; i++ {
		privs := make([]PrivKeyBLS381KOS, NUMSIGNERS)
		pubs := make([]PubKey, NUMSIGNERS)
		sigs := make([]AggregatableSignature, NUMSIGNERS)
		multi := make([]int64, NUMSIGNERS)
		msg := CRandBytes(128)
		for j := 0; j < NUMSIGNERS; j++ {
			x := rand.Int63()
			privs[j] = GenPrivKeyBLS381KOS()
			pubs[j] = privs[j].PubKey()
			sig := privs[j].Sign(msg)
			siga := sig.(AggregatableSignature)
			scaled, ok := siga.Scale(x)
			require.True(t, ok, "Signature scalaing failed")
			sigs[j] = scaled
			multi[j] = x
		}
		var sg SignatureBLS381KOS
		sga, ok := sg.Aggregate(sigs)
		sg = sga.(SignatureBLS381KOS)
		require.True(t, ok, "BLS381KOS signature aggregation failure")
		require.True(t, sg.VerifyBytesWithMultiplicity(pubs, multi, msg), "BLS381KOS multisignature verification failed")
	}
}
