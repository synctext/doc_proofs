package ElementProof_test

import (
	"testing"

	"github.com/skuchain/trade_proofs/ProofElements"
)

func TestInitialStateSha2(t *testing.T) {
	newProof := new(ElementProof.SecP256k1SHA2ElementProof)
	if newProof.State != ElementProof.Initialized {
		t.Error("Secp25k61 Proof should be in the initial state")
	}
}
