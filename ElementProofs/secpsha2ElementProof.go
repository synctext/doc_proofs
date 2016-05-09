package ElementProof

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/skuchain/trade_proofs/ElementProofStore"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/fastsha256"
)

type SecP256k1SHA2ElementProof struct {
	SecP256k1ElementProof
	Preimages [][]byte
	Digests   [][32]byte
}

func (b *SecP256k1SHA2ElementProof) ToBytes() []byte {
	store := ElementProofStore.SECPSHA2ElementProofStore{}
	store.Name = b.ProofName
	store.Data = b.Data
	store.Supercede = b.Supercede
	store.Threshold = int32(b.Threshold)
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
	bufferBytes, err := proto.Marshal(&store)
	if err != nil {
		fmt.Println(err)
	}
	return bufferBytes
}

func (b *SecP256k1SHA2ElementProof) FromBytes(bits []byte) error {
	store := ElementProofStore.SECPSHA2ElementProofStore{}
	err := proto.Unmarshal(bits, &store)
	if err != nil {
		return err
	}
	b.ProofName = store.Name
	b.Data = store.Data
	b.Supercede = store.Supercede
	b.Threshold = int(store.Threshold)
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
		SupercededBy string
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
	case SuperCeded:
		jsonProof.State = "SupercededBy"
	}
	for _, sig := range b.Signatures {
		jsonProof.Signatures = append(jsonProof.Signatures, hex.EncodeToString(sig.Serialize()))
	}
	for _, pubKey := range b.PublicKeys {
		jsonProof.PublicKeys = append(jsonProof.PublicKeys, hex.EncodeToString(pubKey.SerializeCompressed()))
	}
	jsonProof.SupercededBy = b.Supercede
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
