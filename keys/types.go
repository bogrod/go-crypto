package keys

import (
	crypto "github.com/tendermint/go-crypto"
)

// Keybase allows simple CRUD on a keystore, as an aid to signing
type Keybase interface {
	// Sign some bytes
	Sign(name, passphrase string, msg []byte) (crypto.Signature, crypto.PubKey, error)
	// Create a new keypair
	Create(name, passphrase string, algo CryptoAlgo) (info Info, seed string, err error)
	// Recover takes a seedphrase and loads in the key
	Recover(name, passphrase, seedphrase string) (info Info, erro error)
	List() ([]Info, error)
	Get(name string) (Info, error)
	Update(name, oldpass, newpass string) error
	Delete(name, passphrase string) error

	Import(name string, armor string) (err error)
	ImportPubKey(name string, armor string) (err error)
	Export(name string) (armor string, err error)
	ExportPubKey(name string) (armor string, err error)
}

type Info interface {
	GetName() string
	GetPubKey() crypto.PubKey
	GetAddress() []byte
}

var _ Info = &localInfo{}
var _ Info = &ledgerInfo{}

// localInfo is the public information about a locally stored key
type localInfo struct {
	Name         string        `json:"name"`
	PubKey       crypto.PubKey `json:"pubkey"`
	PrivKeyArmor string        `json:"privkey.armor"`
}

func newLocalInfo(name string, pub crypto.PubKey, privArmor string) Info {
	return &localInfo{
		Name:         name,
		PubKey:       pub,
		PrivKeyArmor: privArmor,
	}
}

func (i localInfo) GetName() string {
	return i.Name
}

func (i localInfo) GetPubKey() crypto.PubKey {
	return i.PubKey
}

// Address is a helper function to calculate the address from the pubkey
func (i localInfo) GetAddress() []byte {
	return i.PubKey.Address()
}

// ledgerInfo is the public information about a Ledger key
type ledgerInfo struct {
	Name   string                `json:"name"`
	PubKey crypto.PubKey         `json:"pubkey"`
	Path   crypto.DerivationPath `json:"path"`
}

func newLedgerInfo(name string, pub crypto.PubKey, path crypto.DerivationPath) Info {
	return &ledgerInfo{
		Name:   name,
		PubKey: pub,
		Path:   path,
	}
}

func (i ledgerInfo) GetName() string {
	return i.Name
}

func (i ledgerInfo) GetPubKey() crypto.PubKey {
	return i.PubKey
}

func (i ledgerInfo) GetAddress() []byte {
	return i.PubKey.Address()
}

// encoding
func writeInfo(i Info) []byte {
	bz, err := cdc.MarshalBinaryBare(i)
	if err != nil {
		panic(err)
	}
	return bz
}

// decoding
func readInfo(bz []byte) (info Info, err error) {
	err = cdc.UnmarshalBinaryBare(bz, &info)
	return
}
