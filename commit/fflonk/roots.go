package fflonk

import (
	"errors"
	"math/big"
)

// Function to solve for x in x^n ≡ a (mod p)
// Returns the nth root as a *big.Int and an error if any issues arise
func nthRoot(a, n, p *big.Int) (*big.Int, error) {
	// Check if inputs are valid
	if p.Cmp(big.NewInt(1)) <= 0 {
		return nil, errors.New("p must be a prime number greater than 1")
	}
	if n.Cmp(big.NewInt(0)) <= 0 {
		return nil, errors.New("n must be a positive integer")
	}
	if a.Cmp(big.NewInt(0)) < 0 || a.Cmp(p) > 0 {
		return nil, errors.New("a must be in the range 0 <= a < p")
	}

	pSub := new(big.Int).Sub(p, big.NewInt(1))
	nInverse := new(big.Int).ModInverse(n, pSub)
	if nInverse == nil {
		return nil, errors.New("n no modular inverse exists")
	}

	// Compute the nth root using the inverse of n mod p-1
	result := new(big.Int).Exp(a, nInverse, p)

	return result, nil
}
