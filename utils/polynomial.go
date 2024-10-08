package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type Polynomial struct {
	coeff []*big.Int // coefficients P(x) = coeff[0] + coeff[1] x + ... + coeff[degree] x^degree ...
}

// New returns a polynomial P(x) = 0 with capacity degree + 1
func New(degree int) (Polynomial, error) {
	if degree < 0 {
		return Polynomial{}, fmt.Errorf(fmt.Sprintf("degree must be non-negative, got %d", degree))
	}

	coeff := make([]*big.Int, degree+1)

	for i := 0; i < len(coeff); i++ {
		coeff[i] = big.NewInt(0)
	}

	//set the leading coefficient
	//coeff[len(coeff) - 1].SetInt64(1)

	return Polynomial{coeff}, nil
}

// GetDegree returns the degree, ignoring removing leading zeroes
func (poly Polynomial) GetDegree() int {
	deg := len(poly.coeff) - 1

	// note: i == 0 is not tested, because even the constant term is zero, we consider it's degree 0
	for i := deg; i > 0; i-- {
		if poly.coeff[i].Int64() == 0 {
			deg--
		} else {
			break
		}
	}
	return deg
}

// GetLeadingCoefficient returns the coefficient of the highest degree of the variable
func (poly Polynomial) GetLeadingCoefficient() *big.Int {
	lc := big.NewInt(0)
	lc.Set(poly.coeff[poly.GetDegree()])

	return lc
}

// GetCoefficient returns coeff[i]
func (poly Polynomial) GetCoefficient(i int) (*big.Int, error) {
	if i < 0 || i >= len(poly.coeff) {
		return big.NewInt(0), errors.New("out of boundary")
	}

	return poly.coeff[i], nil
}

// SetCoefficient sets the poly.coeff[i] to ci
func (poly *Polynomial) SetCoefficient(i int, ci int64) error {
	if i < 0 || i >= len(poly.coeff) {
		return errors.New("out of boundary")
	}

	poly.coeff[i].SetInt64(ci)

	return nil
}

// SetCoefficientBig sets the poly.coeff[i] to ci (a gmp.Int)
func (poly *Polynomial) SetCoefficientBig(i int, ci *big.Int) error {
	if i < 0 || i >= len(poly.coeff) {
		return errors.New("out of boundary")
	}

	poly.coeff[i].Set(ci)

	return nil
}

// Reset sets the coefficients to zeroes
func (poly *Polynomial) Reset() {
	for i := 0; i < len(poly.coeff); i++ {
		poly.coeff[i].SetInt64(0)
	}
}

func (poly *Polynomial) DeepCopy(other Polynomial) {
	poly.resetToDegree(other.GetDegree())

	for i := 0; i < other.GetDegree()+1; i++ {
		poly.coeff[i].Set(other.coeff[i])
	}
}

// resetToDegree resizes the slice to degree
func (poly *Polynomial) resetToDegree(degree int) {
	// if we just need to shrink the size
	if degree+1 <= len(poly.coeff) {
		poly.coeff = poly.coeff[:degree+1]
	} else {
		// if we need to grow the slice
		needed := degree + 1 - len(poly.coeff)
		neededPointers := make([]*big.Int, needed)
		for i := 0; i < len(neededPointers); i++ {
			neededPointers[i] = big.NewInt(0)
		}

		poly.coeff = append(poly.coeff, neededPointers...)
	}

	poly.Reset()
}

func (poly Polynomial) Equal(op Polynomial) bool {
	if op.GetDegree() != poly.GetDegree() {
		return false
	}

	for i := 0; i <= op.GetDegree(); i++ {
		if op.coeff[i].Cmp(poly.coeff[i]) != 0 {
			return false
		}
	}

	return true
}

// IsZero returns if poly == 0
func (poly Polynomial) IsZero() bool {
	if poly.GetDegree() != 0 {
		return false
	}

	return poly.coeff[0].Int64() == 0
}

// Rand sets the polynomial coefficients to a pseudo-random number in [0, n)
// WARNING: Rand makes sure that the highest coefficient is not zero
func (poly *Polynomial) Rand(mod *big.Int) {
	for i := range poly.coeff {
		poly.coeff[i], _ = rand.Int(rand.Reader, mod)
	}

	highest := len(poly.coeff) - 1

	for {
		if poly.coeff[highest].Int64() == 0 {
			poly.coeff[highest], _ = rand.Int(rand.Reader, mod)
		} else {
			break
		}
	}

}

func (poly Polynomial) GetCap() int {
	return len(poly.coeff)
}

func (poly *Polynomial) GrowCapTo(cap int) {
	current := poly.GetCap()
	if cap <= current {
		return
	}

	// if we need to grow the slice
	needed := cap - current
	neededPointers := make([]*big.Int, needed)
	for i := 0; i < len(neededPointers); i++ {
		neededPointers[i] = big.NewInt(0)
	}

	poly.coeff = append(poly.coeff, neededPointers...)
}

// NewRand returns a randomized polynomial with specified degree
// coefficients are pesudo-random numbers in [0, n)
func NewRand(degree int, n *big.Int) (Polynomial, error) {
	p, e := New(degree)
	if e != nil {
		return Polynomial{}, e
	}

	p.Rand(n)

	return p, nil
}

// NewConstant returns create a constant polynomial P(x) = c
func NewConstant(c int64) Polynomial {
	zero, err := New(0)
	if err != nil {
		panic(err.Error())
	}

	zero.coeff[0] = big.NewInt(c)
	return zero
}

// NewOne creates a constant polynomial P(x) = 1
func NewOne() Polynomial {
	return NewConstant(1)
}

// NewEmpty creates a constant polynomial P(x) = 0
func NewEmpty() Polynomial {
	return NewConstant(0)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Mod sets poly to poly % p
func (poly *Polynomial) Mod(p *big.Int) {
	for i := 0; i < len(poly.coeff); i++ {
		poly.coeff[i].Mod(poly.coeff[i], p)
	}
}

// Add sets poly to op1 + op2
func (poly *Polynomial) Add(op1 Polynomial, op2 Polynomial) error {
	// make sure poly is as long as the longest of op1 and op2
	deg1 := op1.GetDegree()
	deg2 := op2.GetDegree()

	if deg1 > deg2 {
		poly.DeepCopy(op1)

	} else {
		poly.DeepCopy(op2)
	}
	for i := 0; i < min(deg1, deg2)+1; i++ {
		poly.coeff[i].Add(op1.coeff[i], op2.coeff[i])
	}
	return nil
}

// AddSelf sets poly to poly + op
func (poly *Polynomial) AddSelf(op Polynomial) error {
	var op1 Polynomial
	op1.DeepCopy(*poly)
	return poly.Add(op1, op)
}

// Sub sets poly to op1 - op2
func (poly *Polynomial) Sub(op1 Polynomial, op2 Polynomial) error {
	// make sure poly is as long as the longest of op1 and op2
	deg1 := op1.GetDegree()
	deg2 := op2.GetDegree()

	if deg1 > deg2 {
		poly.DeepCopy(op1)
	} else {
		poly.DeepCopy(op2)
	}

	for i := 0; i < min(deg1, deg2)+1; i++ {
		poly.coeff[i].Sub(op1.coeff[i], op2.coeff[i])
	}
	poly.coeff = poly.coeff[:poly.GetDegree()+1]

	return nil
}

// SubSelf sets poly to poly - op
func (poly *Polynomial) SubSelf(op Polynomial) error {
	// make sure poly is as long as the longest of op1 and op2
	deg1 := op.GetDegree()

	poly.GrowCapTo(deg1 + 1)

	for i := 0; i < deg1+1; i++ {
		poly.coeff[i].Sub(poly.coeff[i], op.coeff[i])
	}

	poly.coeff = poly.coeff[:poly.GetDegree()+1]

	// FIXME: no need to return error
	return nil
}

// AddMul sets poly to poly + poly2 * k (k being a scalar)
func (poly *Polynomial) AddMul(poly2 Polynomial, k *big.Int) {
	for i := 0; i <= poly2.GetDegree(); i++ {
		tmp := new(big.Int).Mul(poly2.coeff[i], k)
		poly.coeff[i].Add(poly.coeff[i], tmp)
	}
}

// Mul set poly to op1 * op2
func (poly *Polynomial) Mul(op1 Polynomial, op2 Polynomial) error {
	deg1 := op1.GetDegree()
	deg2 := op2.GetDegree()

	poly.resetToDegree(deg1 + deg2)

	for i := 0; i <= deg1; i++ {
		for j := 0; j <= deg2; j++ {
			tmp := new(big.Int).Mul(op1.coeff[i], op2.coeff[j])
			poly.coeff[i+j].Add(poly.coeff[i+j], tmp)
		}
	}

	poly.coeff = poly.coeff[:poly.GetDegree()+1]

	return nil
}

// EvalMod returns poly(x) using Horner's rule. If p != nil, returns poly(x) mod p
func (poly Polynomial) EvalMod(x *big.Int, p *big.Int) *big.Int {
	result := new(big.Int).Set(poly.coeff[poly.GetDegree()])

	for i := poly.GetDegree(); i >= 1; i-- {
		result.Mul(result, x)
		result.Add(result, poly.coeff[i-1])
	}

	if p != nil {
		result.Mod(result, p)
	}
	return result
}

// DivMod sets computes q, r such that a = b*q + r.
// This is an implementation of Euclidean division. The complexity is O(n^3)!!
func DivMod(a Polynomial, b Polynomial, p *big.Int) (Polynomial, Polynomial, error) {
	if b.IsZero() {
		return Polynomial{}, Polynomial{}, errors.New("divide by zero")
	}

	var q, r Polynomial

	q.resetToDegree(0)
	r.DeepCopy(a)

	d := b.GetDegree()
	c := b.GetLeadingCoefficient()

	// cInv = 1/c
	cInv := big.NewInt(0)
	cInv.ModInverse(c, p)

	for r.GetDegree() >= d {
		lc := r.GetLeadingCoefficient()
		s, err := New(r.GetDegree() - d)
		if err != nil {
			return Polynomial{}, Polynomial{}, err
		}

		err = s.SetCoefficientBig(r.GetDegree()-d, lc.Mul(lc, cInv))
		if err != nil {
			return Polynomial{}, Polynomial{}, err
		}
		q.AddSelf(s)

		sb := NewEmpty()
		sb.Mul(s, b)

		// deg r reduces by each iteration
		r.SubSelf(sb)

		// modulo p
		q.Mod(p)
		r.Mod(p)
	}

	return q, r, nil
}

func FromVec(coeff ...int64) Polynomial {
	if len(coeff) == 0 {
		return NewConstant(0)
	}
	deg := len(coeff) - 1

	poly, err := New(deg)
	if err != nil {
		panic(err.Error())
	}

	for i := range poly.coeff {
		poly.coeff[i].SetInt64(coeff[i])
	}

	return poly
}

func (poly Polynomial) ToString() string {
	var s = ""

	for i := len(poly.coeff) - 1; i >= 0; i-- {
		// skip zero coefficients but the constant term
		if i != 0 && poly.coeff[i].Int64() == 0 {
			continue
		}
		if i > 0 {
			s += fmt.Sprintf("%s x^%d + ", poly.coeff[i].String(), i)
		} else {
			// constant term
			s += poly.coeff[i].String()
		}
	}

	return s
}
