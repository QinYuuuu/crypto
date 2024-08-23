package main

import (
	"crypto/rand"
	"fmt"
	"github.com/QinYuuuu/crypto/elgamal"
	"go.dedis.ch/kyber/v3/group/curve25519"
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

// MeasureTime measures the execution time of a simulation function.
func MeasureTime(simulateFunc func(B, n int, p, g, pElgamal, gElgamal *big.Int), B, n int, p, g, pElgamal, gElgamal *big.Int) time.Duration {
	startTime := time.Now()
	simulateFunc(B, n, p, g, pElgamal, gElgamal)
	return time.Since(startTime)
}

func main() {
	suite := curve25519.NewBlakeSHA256Curve25519(true)
	// Create a public/private keypair
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	A := suite.Point().Mul(a, nil)                 // Alice's public key
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}
	elgamal.Encrypt(suite, A, key)
	BRange := []int{2, 4, 8, 16, 32, 64, 128}
	nRange := []int{2, 4, 8, 16, 32, 64, 128}

	var test1BTimes, test2BTimes, test1NTimes, test2NTimes []time.Duration
	/*
		for _, B := range BRange {
			fmt.Println(B)
			test1BTimes = append(test1BTimes, MeasureTime(SimulateTest1, B, 5, p, g, pElgamal, gElgamal))
			test2BTimes = append(test2BTimes, MeasureTime(SimulateTest2, B, 5, p, g, pElgamal, gElgamal))
		}

		for _, n := range nRange {
			fmt.Println(n)
			test1NTimes = append(test1NTimes, MeasureTime(SimulateTest1, 5, n, p, g, pElgamal, gElgamal))
			test2NTimes = append(test2NTimes, MeasureTime(SimulateTest2, 5, n, p, g, pElgamal, gElgamal))
		}*/
}
