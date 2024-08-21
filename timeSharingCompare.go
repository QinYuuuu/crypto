package main

import (
	"crypto/rand"
	"math/big"
	"time"
)

// GeneratePrime generates a prime number of the specified bit length.
func GeneratePrime(bits int) *big.Int {
	prime, _ := rand.Prime(rand.Reader, bits)
	return prime
}

// FindPrimitiveRoot finds a primitive root for a prime p.
func FindPrimitiveRoot(p *big.Int) *big.Int {
	if p.Cmp(big.NewInt(2)) == 0 {
		return big.NewInt(1)
	}
	p1 := big.NewInt(2)
	p2 := new(big.Int).Sub(p, big.NewInt(1))
	p2.Div(p2, p1)

	for {
		g, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
		g.Add(g, big.NewInt(2))

		if new(big.Int).Exp(g, new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), p1), p).Cmp(big.NewInt(1)) != 0 &&
			new(big.Int).Exp(g, new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), p2), p).Cmp(big.NewInt(1)) != 0 {
			return g
		}
	}
}

// GenerateLargePrimeAndRoot generates a large prime and its primitive root.
func GenerateLargePrimeAndRoot(bits int) (*big.Int, *big.Int) {
	p := GeneratePrime(bits)
	g := FindPrimitiveRoot(p)
	return p, g
}

// ElGamalEncrypt encrypts the values using the ElGamal encryption scheme.
func ElGamalEncrypt(values []*big.Int, publicKey [2]*big.Int, p *big.Int) [][2]*big.Int {
	g, h := publicKey[0], publicKey[1]
	encryptedValues := make([][2]*big.Int, len(values))
	k, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	c1 := new(big.Int).Exp(g, k, p)
	tmp := new(big.Int).Exp(h, k, p)

	for i, value := range values {
		c2 := new(big.Int).Mul(value, tmp)
		c2.Mod(c2, p)
		encryptedValues[i] = [2]*big.Int{c1, c2}
	}

	return encryptedValues
}

// MeasureTime measures the execution time of a simulation function.
func MeasureTime(simulateFunc func(B, n int, p, g, pElgamal, gElgamal *big.Int), B, n int, p, g, pElgamal, gElgamal *big.Int) time.Duration {
	startTime := time.Now()
	simulateFunc(B, n, p, g, pElgamal, gElgamal)
	return time.Since(startTime)
}

/*
func main() {
	bitsElgamal := 1024
	pElgamal, gElgamal := GenerateLargePrimeAndRoot(bitsElgamal)
	bits := 128
	p, g := GenerateLargePrimeAndRoot(bits)

	BRange := []int{2, 4, 8, 16, 32, 64, 128}
	nRange := []int{2, 4, 8, 16, 32, 64, 128}

	var test1BTimes, test2BTimes, test1NTimes, test2NTimes []time.Duration

	for _, B := range BRange {
		fmt.Println(B)
		test1BTimes = append(test1BTimes, MeasureTime(SimulateTest1, B, 5, p, g, pElgamal, gElgamal))
		test2BTimes = append(test2BTimes, MeasureTime(SimulateTest2, B, 5, p, g, pElgamal, gElgamal))
	}

	for _, n := range nRange {
		fmt.Println(n)
		test1NTimes = append(test1NTimes, MeasureTime(SimulateTest1, 5, n, p, g, pElgamal, gElgamal))
		test2NTimes = append(test2NTimes, MeasureTime(SimulateTest2, 5, n, p, g, pElgamal, gElgamal))
	}
}
*/
