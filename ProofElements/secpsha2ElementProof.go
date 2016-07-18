/*
Copyright (c) 2016 Skuchain,Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package ElementProof

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/skuchain/trade_proofs/ProofElementStore"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/fastsha256"
)

type SecP256k1SHA2ElementProof struct {
	SecP256k1ElementProof
	Preimages [][]byte
	Digests   [][32]byte
}

func (b *SecP256k1SHA2ElementProof) ToBytes() []byte {
	store := ProofElementStore.SECPSHA2ProofElementStore{}
	store.Name = b.ProofName
	store.Data = b.Data
	store.SupersededBy = b.SupersededBy
	store.Threshold = int32(b.Threshold)
	switch b.State {
	case Initialized:
		store.State = ProofElementStore.SECPSHA2ProofElementStore_Initialized
	case Signed:
		store.State = ProofElementStore.SECPSHA2ProofElementStore_Signed
	case Revoked:
		store.State = ProofElementStore.SECPSHA2ProofElementStore_Revoked
	case Superseded:
		store.State = ProofElementStore.SECPSHA2ProofElementStore_Superseded
	}
	for _, key := range b.PublicKeys {
		store.PublicKeys = append(store.PublicKeys, key.SerializeCompressed())
	}
	for _, sigs := range b.Signatures {
		store.Signatures = append(store.Signatures, sigs.Serialize())
	}
	for _, digest := range b.Digests {
		store.Digests = append(store.Digests, digest[:])
	}

	for _, preimage := range b.Preimages {
		store.Preimages = append(store.Preimages, preimage[:])
	}

	metastore := ProofElementStore.ProofElementStore{}
	metastore.Type = ProofElementStore.ProofElementStore_SECPSHA
	metastore.Secpsha = &store

	bufferBytes, err := proto.Marshal(&metastore)
	if err != nil {
		fmt.Println(err)
	}
	return bufferBytes
}

func (b *SecP256k1SHA2ElementProof) FromBytes(bits []byte) error {
	metastore := ProofElementStore.ProofElementStore{}
	err := proto.Unmarshal(bits, &metastore)
	if err != nil {
		return err
	}
	if metastore.Type != ProofElementStore.ProofElementStore_SECPSHA {
		return errors.New("Expected SECPSHA2 proof")
	}
	store := metastore.Secpsha
	b.ProofName = store.Name
	b.Data = store.Data
	b.SupersededBy = store.SupersededBy
	b.Threshold = int(store.Threshold)
	switch store.State {
	case ProofElementStore.SECPSHA2ProofElementStore_Initialized:
		b.State = Initialized
	case ProofElementStore.SECPSHA2ProofElementStore_Signed:
		b.State = Signed
	case ProofElementStore.SECPSHA2ProofElementStore_Revoked:
		b.State = Revoked
	case ProofElementStore.SECPSHA2ProofElementStore_Superseded:
		b.State = Superseded
	}
	for _, key := range store.PublicKeys {
		publicKey, err := btcec.ParsePubKey(key, btcec.S256())
		if err != nil {
			return err
		}
		b.PublicKeys = append(b.PublicKeys, *publicKey)
	}
	for _, sig := range store.Signatures {
		signature, err := btcec.ParseSignature(sig, btcec.S256())
		if err != nil {
			return err
		}
		b.Signatures = append(b.Signatures, *signature)
	}
	for _, digest := range store.Digests {
		var static [32]byte
		copy(static[:], digest)
		b.Digests = append(b.Digests, static)
	}
	for _, preimage := range store.Preimages {
		b.Preimages = append(b.Preimages, preimage)
	}
	return nil
}

func (b *SecP256k1SHA2ElementProof) Hash(preImages [][]byte) bool {
	count := 0
	usedDigests := make([]bool, len(b.Digests))
	hasher := fastsha256.New()
	for _, preImage := range preImages {
		imageDigestRaw := hasher.Sum(preImage)
		hasher.Reset()
		var imageDigest [32]byte
		copy(imageDigest[:], imageDigestRaw)
		for i, digest := range b.Digests {
			if (digest == imageDigest) && usedDigests[i] == false {
				usedDigests[i] = true
				count = count + 1
			}
		}
	}
	if count != len(b.Digests) {
		return false
	}
	b.Preimages = preImages
	return true
}

func (b *SecP256k1SHA2ElementProof) ToJSON() []byte {
	type JSONProof struct {
		ProofName    string
		State        string
		Signatures   []string
		PublicKeys   []string
		SupersededBy string
		Threshold    int
		Data         string
		Digests      []string
		Preimages    []string
	}
	jsonProof := JSONProof{}

	jsonProof.ProofName = b.ProofName
	switch b.State {
	case Initialized:
		jsonProof.State = "Initialized"
	case Signed:
		jsonProof.State = "Signed"
	case Revoked:
		jsonProof.State = "Revoked"
	case Superseded:
		jsonProof.State = "SupercededBy"
	}
	for _, sig := range b.Signatures {
		jsonProof.Signatures = append(jsonProof.Signatures, hex.EncodeToString(sig.Serialize()))
	}
	for _, pubKey := range b.PublicKeys {
		jsonProof.PublicKeys = append(jsonProof.PublicKeys, hex.EncodeToString(pubKey.SerializeCompressed()))
	}
	jsonProof.SupersededBy = b.SupersededBy
	jsonProof.Threshold = b.Threshold
	jsonProof.Data = b.Data
	for _, digest := range b.Digests {
		jsonProof.Digests = append(jsonProof.Digests, hex.EncodeToString(digest[:]))
	}
	for _, preimage := range b.Preimages {
		jsonProof.Preimages = append(jsonProof.Preimages, hex.EncodeToString(preimage[:]))
	}

	jsonstring, err := json.Marshal(jsonProof)
	if err != nil {
		return nil
	}
	return jsonstring
}
