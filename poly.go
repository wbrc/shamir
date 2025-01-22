package shamir

import (
	"errors"

	"github.com/wbrc/gf65536"
)

func gauss(f gf65536.Field, m [][]uint16) error {
	// upper triangular form
	for r := 0; r < len(m); r++ {
		if m[r][r] == 0 {
			i := findNonzero(m, r)
			if i == -1 {
				return errors.New("matrix is singular")
			}
			m[r], m[i] = m[i], m[r]
		}

		for i := r; i < len(m); i++ {
			if m[i][r] == 0 {
				continue
			}
			scalePoly(f, m[i], m[i], f.Inv(m[i][r]))
		}

		for i := r + 1; i < len(m); i++ {
			if m[i][r] == 0 {
				continue
			}
			addPoly(f, m[i], m[i], m[r])
		}
	}

	// back substitute to have row[0] = [1, 0, 0, ..., secret]
	for r := 1; r < len(m); r++ {
		scalePoly(f, m[r], m[r], m[0][r])
		addPoly(f, m[0], m[0], m[r])
	}

	return nil
}

// return index of first row in m[r:] where the element at column r is nonzero
// or -1 otherwise
func findNonzero(m [][]uint16, r int) int {
	for i := r; i < len(m); i++ {
		if m[i][r] != 0 {
			return i
		}
	}

	return -1
}

// set v to [x^0, x^1, x^2, ...]
func pows(f gf65536.Field, v []uint16, x uint16) {
	var p uint16 = 1
	for i := 0; i < len(v); i++ {
		v[i] = p
		p = f.Mul(p, x)
	}
}

func evalPoly(f gf65536.Field, coeff []uint16, x uint16) uint16 {
	var p, r uint16 = 1, 0
	for i := 0; i < len(coeff); i++ {
		r = f.Add(r, f.Mul(p, coeff[i]))
		p = f.Mul(p, x)
	}

	return r
}

func scalePoly(f gf65536.Field, z, coeff []uint16, x uint16) {
	for i := 0; i < len(coeff); i++ {
		z[i] = f.Mul(coeff[i], x)
	}
}

func addPoly(f gf65536.Field, z, a, b []uint16) {
	for i := 0; i < len(a); i++ {
		z[i] = f.Add(a[i], b[i])
	}
}
