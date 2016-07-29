/*
Copyright (c) 2016 Skuchain,Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package ElementProof_test

import (
	"testing"

	"github.com/skuchain/doc_proofs/ProofElements"
)

func TestInitialState(t *testing.T) {
	newProof := new(ElementProof.SecP256k1ElementProof)
	if newProof.State != ElementProof.Initialized {
		t.Error("Secp25k61 Proof should be in the initial state")
	}
}

func TestInvalidSign(t *testing.T) {
	newProof := new(ElementProof.SecP256k1ElementProof)
	var sigs [][]byte
	if newProof.Signed(&sigs, "") != false || newProof.State != ElementProof.Initialized {
		t.Error("Signed without signatures should fail")
	}
}

func TestInvalidRevoke(t *testing.T) {
	newProof := new(ElementProof.SecP256k1ElementProof)
	var sigs [][]byte
	if newProof.Revoked(&sigs) != false || newProof.State != ElementProof.Initialized {
		t.Error("Revoke without signatures should fail")
	}
}

// func TestInvalidPublicKey(t *testing.T) {
// 	newProof := new(ElementProof.SecP256k1ElementProof)
// 	count := []int{0, 1, 2}
// 	for _ = range count {
// 	}
// }
