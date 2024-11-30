package fflonk

import (
	"math/big"
	"testing"
)

// Helper function to compare big.Int values in tests
func bigIntEqual(a, b *big.Int) bool {
	return a.Cmp(b) == 0
}

// Test cases for the nthRoot function
func TestNthRoot(t *testing.T) {
	tests := []struct {
		a, n, p  *big.Int // Inputs: a, n, p
		expected *big.Int // Expected result
		err      bool     // Whether we expect an error
	}{
		// Valid test cases
		{big.NewInt(4), big.NewInt(3), big.NewInt(17), big.NewInt(13), false}, // 8^3 ≡ 4 mod 17
		{big.NewInt(1), big.NewInt(5), big.NewInt(11), big.NewInt(1), false},  // 1^5 ≡ 1 mod 11

		// Invalid test cases (expect errors)
		{big.NewInt(4), big.NewInt(3), big.NewInt(1), nil, true},   // p must be greater than 1
		{big.NewInt(4), big.NewInt(-2), big.NewInt(17), nil, true}, // n must be positive
		{big.NewInt(4), big.NewInt(2), big.NewInt(17), nil, true},  // n does not divide p-1 (16 % 2 != 0)
		{big.NewInt(-1), big.NewInt(3), big.NewInt(17), nil, true}, // a is negative
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			result, err := nthRoot(test.a, test.n, test.p)

			// Check if we expect an error
			if test.err {
				if err == nil {
					t.Errorf("Expected an error for a=%d, n=%d, p=%d but got none", test.a, test.n, test.p)
				}
			} else {
				if err != nil {
					t.Errorf("Did not expect an error for a=%d, n=%d, p=%d but got %v", test.a, test.n, test.p, err)
				}
				// Compare the result with the expected value
				if !bigIntEqual(result, test.expected) {
					t.Errorf("For a=%d, n=%d, p=%d, expected %v, but got %v", test.a, test.n, test.p, test.expected, result)
				}
			}
		})
	}
}
