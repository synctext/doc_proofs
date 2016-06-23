package ElementProof_test

import (
	"testing"

	"github.com/skuchain/trade_proofs/ProofElements"
)

func TestInitialState(t *testing.T) {
	newProof := new(ElementProof.SecP256k1ElementProof)
	if newProof.State != ElementProof.Initialized {
		t.Error("Secp25k61 Proof should be in the initial state")
	}
}

func TestInvalidRevoke(t *testing.T) {
	newProof := new(ElementProof.SecP256k1ElementProof)
	var sigs [][]byte
	if newProof.Revoked(&sigs) != false || newProof.State != ElementProof.Initialized {
		t.Error("Revoke without signatures should fail")
	}
}

func TestInvalidSign(t *testing.T) {
	newProof := new(ElementProof.SecP256k1ElementProof)
	var sigs [][]byte
	if newProof.Signed(&sigs, "") != false || newProof.State != ElementProof.Initialized {
		t.Error("Signed without signatures should fail")
	}
}
