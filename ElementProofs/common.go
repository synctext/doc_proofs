package ElementProof

type SigState int

const (
	Initialized SigState = iota // 0
	Signed                      // 1
	Revoked                     // 2
	SuperCeded                  // 3
)
