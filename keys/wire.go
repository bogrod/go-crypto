package keys

import (
	amino "github.com/tendermint/go-amino"
	crypto "github.com/tendermint/go-crypto"
)

var cdc = amino.NewCodec()

func init() {
	crypto.RegisterAmino(cdc)
	amino.RegisterInterface((*Info)(nil), nil)
	amino.RegisterConcrete(ledgerInfo{}, "crypto/keys/ledgerInfo", nil)
	amino.RegisterConcrete(localInfo{}, "crypto/keys/localInfo", nil)
}
