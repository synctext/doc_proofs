package ElementProof

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	// "github.com/Skuchain/trade_proofs/ElementProofStore"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/fastsha256"
	"github.com/golang/protobuf/proto"
	"github.com/skuchain/trade_proofs/ProofElementStore"
)

type SecP256k1ElementProof struct {
	ProofName  string
	State      SigState
	Signatures []btcec.Signature
	PublicKeys []btcec.PublicKey
	Supersede  string
	Threshold  int
	Data       string
}

//PubKeys hello
func (b *SecP256k1ElementProof) PubKeys() []string {
	output := *new([]string)
	for _, key := range b.PublicKeys {
		output = append(output, hex.EncodeToString(key.SerializeCompressed()))
	}
	return output
}

func (b *SecP256k1ElementProof) CurrentState() SigState {
	return b.State
}

func (b *SecP256k1ElementProof) Name() string {
	return b.ProofName
}

func (b *SecP256k1ElementProof) verifySigs(message string, signatures *[][]byte) (bool, []btcec.Signature) {
	validSig := false
	validatedSigs := *new([]btcec.Signature)
	usedKeys := make([]bool, len(b.PublicKeys))
	messageBytes := fastsha256.Sum256([]byte(message))
	for _, sigbytes := range *signatures {

		signature, err := btcec.ParseDERSignature(sigbytes, btcec.S256())
		if err != nil {
			fmt.Println("Bad signature encoding")
			return false, nil
		}
		validSig = false

		for i, pubKey := range b.PublicKeys {
			success := signature.Verify(messageBytes[:], &pubKey)
			if success && (usedKeys[i] == false) {
				validSig = true
				validatedSigs = append(validatedSigs, *signature)
				usedKeys[i] = true
			}
		}
	}

	if validSig == false {
		return false, nil
	}
	if len(validatedSigs) < b.Threshold {
		return false, nil
	}
	return validSig, validatedSigs
}
func (b *SecP256k1ElementProof) SuperSede(signatures *[][]byte, supersededBy string) bool {

	success, sigs := b.verifySigs(b.ProofName+":Superseded", signatures)
	if !success {
		return false
	}

	if b.State == Initialized || b.State == Signed || b.State == Revoked {
		b.State = Superseded
		b.Supersede = supersededBy
		b.Signatures = sigs
		return true
	}
	return false
}

func (b *SecP256k1ElementProof) Revoked(signatures *[][]byte) bool {

	success, sigs := b.verifySigs(b.ProofName+":revoked", signatures)
	if !success {
		return false
	}

	if b.State == Initialized || b.State == Signed {
		b.State = Revoked
		b.Signatures = sigs
		return true
	}
	return false
}

func (b *SecP256k1ElementProof) Signed(signatures *[][]byte, data string) bool {

	success, sigs := b.verifySigs(b.ProofName+":"+data, signatures)
	if !success {
		return false
	}
	if b.State == Initialized {
		b.State = Signed
		b.Signatures = sigs
		b.Data = data
		return true
	}
	return false
}

func (b *SecP256k1ElementProof) Fulfillment() string {

	return "Not Implemented Yet"
}

func (b *SecP256k1ElementProof) ToBytes() []byte {
	store := ProofElementStore.SECPProofElementStore{}
	store.Name = b.ProofName
	store.Data = b.Data
	store.SupersededBy = b.Supersede
	store.Threshold = int32(b.Threshold)
	switch b.State {
	case Initialized:
		store.State = ProofElementStore.SECPProofElementStore_Initialized
	case Signed:
		store.State = ProofElementStore.SECPProofElementStore_Signed
	case Revoked:
		store.State = ProofElementStore.SECPProofElementStore_Revoked
	case Superseded:
		store.State = ProofElementStore.SECPProofElementStore_Superseded
	}

	for _, key := range b.PublicKeys {
		store.PublicKeys = append(store.PublicKeys, key.SerializeCompressed())
	}
	for _, sigs := range b.Signatures {
		store.Signatures = append(store.Signatures, sigs.Serialize())
	}
	bufferBytes, err := proto.Marshal(&store)
	if err != nil {
		fmt.Println(err)
	}
	return bufferBytes
}

func (b *SecP256k1ElementProof) FromBytes(bits []byte) error {
	store := ProofElementStore.SECPProofElementStore{}
	err := proto.Unmarshal(bits, &store)
	if err != nil {
		return err
	}
	b.ProofName = store.Name
	b.Data = store.Data
	b.Supersede = store.SupersededBy
	b.Threshold = int(store.Threshold)
	switch store.State {
	case ProofElementStore.SECPProofElementStore_Initialized:
		b.State = Initialized
	case ProofElementStore.SECPProofElementStore_Signed:
		b.State = Signed
	case ProofElementStore.SECPProofElementStore_Revoked:
		b.State = Revoked
	case ProofElementStore.SECPProofElementStore_Superseded:
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
	return nil
}

func (b *SecP256k1ElementProof) SupersededBy() string {
	return b.Supersede
}

func (b *SecP256k1ElementProof) ToJSON() []byte {
	type JSONBracket struct {
		ProofName    string
		State        string
		Signatures   []string
		PublicKeys   []string
		SupersededBy string
		Threshold    int
		Data         string
	}
	jsonBracket := JSONBracket{}

	jsonBracket.ProofName = b.ProofName
	switch b.State {
	case Initialized:
		jsonBracket.State = "Initialized"
	case Signed:
		jsonBracket.State = "Signed"
	case Revoked:
		jsonBracket.State = "Revoked"
	case Superseded:
		jsonBracket.State = "Superseded"
	}
	for _, sig := range b.Signatures {
		jsonBracket.Signatures = append(jsonBracket.Signatures, hex.EncodeToString(sig.Serialize()))
	}
	for _, pubKey := range b.PublicKeys {
		jsonBracket.PublicKeys = append(jsonBracket.PublicKeys, hex.EncodeToString(pubKey.SerializeCompressed()))
	}
	jsonBracket.SupersededBy = b.Supersede
	jsonBracket.Threshold = b.Threshold
	jsonBracket.Data = b.Data

	jsonstring, err := json.Marshal(jsonBracket)
	if err != nil {
		return nil
	}
	return jsonstring
}