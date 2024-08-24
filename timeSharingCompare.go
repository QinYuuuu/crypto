package main

import (
	"crypto/rand"
	"fmt"
	"github.com/QinYuuuu/crypto/elgamal"
	"github.com/QinYuuuu/crypto/utils"
	"github.com/QinYuuuu/crypto/utils/polynomial"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/curve25519"
	"math/big"
	"time"
)

// MeasureTime measures the execution time of a simulation function.
func MeasureTime(simulateFunc func(B, n int, p, g, pElgamal, gElgamal *big.Int), B, n int, p, g, pElgamal, gElgamal *big.Int) time.Duration {
	startTime := time.Now()
	simulateFunc(B, n, p, g, pElgamal, gElgamal)
	return time.Since(startTime)
}

func evaluatePolynomials(polys []polynomial.Polynomial, n int, p *big.Int) [][]*big.Int {
	evals := make([][]*big.Int, len(polys))
	for k, poly := range polys {
		evals[k] = make([]*big.Int, n)
		for i := 0; i < n; i++ {
			evals[k][i] = poly.EvalMod(new(big.Int).SetInt64(int64(i)), p)
		}
	}
	return evals
}

func simulate_test1(B, n, t int, g kyber.Point, p *big.Int, suite kyber.Group, pk kyber.Point, sk kyber.Scalar) ([][]*big.Int, kyber.Point, kyber.Point) {

	// Generate B+n random polynomials of degree n
	polynomials := make([]polynomial.Polynomial, B+n)
	for i := 0; i < B+n; i++ {
		polynomials[i], _ = polynomial.NewRand(t, p)
	}

	// Evaluate polynomials at each point i in [1, n]
	evals := evaluatePolynomials(polynomials, n, p)

	// Encrypt all evaluations at each point using symmetric enc and Encrypt
	key := utils.RandomNum(p)
	K, C, _ := elgamal.Encrypt(suite, pk, key.Bytes())
	for i := 0; i < B+n; i++ {
		for j := 0; j < t; j++ {
		}
	}
	encryptedValuesPerPoint := make([][]*big.Int, len(polynomials))
	for i := 0; i < len(polynomials); i++ {
		for j := 0; j < n; j++ {
			encryptedValuesPerPoint[i][j] = new(big.Int).Add(key, evals[i][j])
		}
	}
	return encryptedValuesPerPoint, K, C
}

func simulateTest2(B, n, t int, p *big.Int) {
	fs := [generate_random_polynomial(n, p) for _ in range(B)]
	gs = [generate_random_polynomial(n, p) for _ in range(n)]
	points = list(range(1, n + 1))
	evals = evaluate_polynomials(fs, points, p)
	evals = evaluate_polynomials(gs, points, p)
	random_linear_combination(fs, gs, points, p)
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
