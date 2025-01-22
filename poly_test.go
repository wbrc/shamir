package shamir

import (
	"reflect"
	"testing"

	"github.com/wbrc/gf65536"
)

var f = gf65536.Default

func Test_gauss(t *testing.T) {
	poly := []uint16{5890, 301, 30222, 12345} // poly[0] is the secret
	xvals := []uint16{10, 55, 16, 1111}       // 4 samples needed for interpolation

	// x0^0 x0^1 x0^2 x0^3 | y0
	// x1^0 x1^1 x1^2 x1^3 | y1
	// x2^0 x2^1 x2^2 x2^3 | y2
	// x3^0 x3^1 x3^2 x3^3 | y3
	m := make([][]uint16, len(poly))
	for i := range m {
		m[i] = make([]uint16, len(poly)+1)
		pows(f, m[i], xvals[i])
		m[i][len(poly)] = evalPoly(f, poly, xvals[i])
	}

	if err := gauss(f, m); err != nil {
		t.Error(err)
	}

	if m[0][len(m[0])-1] != poly[0] {
		t.Error("gauss failed")
	}
}

func Test_gauss_unsolvable(t *testing.T) {
	err := gauss(f, [][]uint16{
		{0, 1, 1, 9},
		{2, 4, 7, 8},
		{0, 0, 0, 7},
	})
	if err == nil {
		t.Error("expected error")
	}
}

func Test_findNonzero(t *testing.T) {
	type args struct {
		m [][]uint16
		r int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			"ok",
			args{[][]uint16{
				{0, 1, 1},
				{1, 1, 1},
				{2, 1, 1},
			}, 0}, 1,
		},
		{
			"ok",
			args{[][]uint16{
				{0, 1, 1},
				{0, 1, 1},
				{2, 1, 1},
			}, 0}, 2,
		},
		{
			"nok",
			args{[][]uint16{
				{1, 0, 1},
				{1, 0, 1},
				{2, 0, 1},
			}, 1}, -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findNonzero(tt.args.m, tt.args.r); got != tt.want {
				t.Errorf("findNonzero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pows(t *testing.T) {
	type args struct {
		want []uint16
		x    uint16
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "2^x",
			args: args{[]uint16{1, 2, f.Mul(2, 2), f.Mul(2, f.Mul(2, 2))}, 2},
		},
		{
			name: "4888^x",
			args: args{[]uint16{1, 4888, f.Mul(4888, 4888), f.Mul(4888, f.Mul(4888, 4888))}, 4888},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := make([]uint16, len(tt.args.want))
			pows(f, v, tt.args.x)
			if !reflect.DeepEqual(v, tt.args.want) {
				t.Errorf("pows() = %v, want %v", v, tt.args.want)
			}
		})
	}
}

func Test_evalPoly(t *testing.T) {

	if evalPoly(f, []uint16{}, 0) != 0 {
		t.Error("evalPoly failed for empty polynomial")
	}

	if evalPoly(f, []uint16{69}, 1) != 69 {
		t.Error("evalPoly failed for constant polynomial")
	}

	// p(x) = 5890 + 301*x + 30222*x^2 + 12345*x^3
	poly := []uint16{5890, 301, 30222, 12345}
	p0 := f.Add(f.Add(5890, f.Mul(301, 0)), f.Add(f.Mul(30222, 0), f.Mul(12345, 0)))
	p1 := f.Add(f.Add(5890, f.Mul(301, 1)), f.Add(f.Mul(30222, 1), f.Mul(12345, 1)))
	p2 := f.Add(f.Add(5890, f.Mul(301, 2)), f.Add(f.Mul(30222, f.Mul(2, 2)), f.Mul(12345, f.Mul(2, f.Mul(2, 2)))))
	p9 := f.Add(f.Add(5890, f.Mul(301, 9)), f.Add(f.Mul(30222, f.Mul(9, 9)), f.Mul(12345, f.Mul(9, f.Mul(9, 9)))))

	if evalPoly(f, poly, 0) != p0 {
		t.Error("evalPoly failed for x = 0")
	}

	if evalPoly(f, poly, 1) != p1 {
		t.Error("evalPoly failed for x = 1")
	}

	if evalPoly(f, poly, 2) != p2 {
		t.Error("evalPoly failed for x = 2")
	}

	if evalPoly(f, poly, 9) != p9 {
		t.Error("evalPoly failed for x = 9")
	}
}

func Test_scalePoly(t *testing.T) {
	type args struct {
		coeff []uint16
		x     uint16
	}
	tests := []struct {
		name string
		args args
		want []uint16
	}{
		{
			args: args{[]uint16{5890, 301, 30222, 12345}, 0},
			want: []uint16{0, 0, 0, 0},
		},
		{
			args: args{[]uint16{5890, 301, 30222, 12345}, 1},
			want: []uint16{5890, 301, 30222, 12345},
		},
		{
			args: args{[]uint16{2, 4, 6, 8}, 2},
			want: []uint16{4, 8, 12, 16},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make([]uint16, len(tt.args.coeff))
			scalePoly(f, got, tt.args.coeff, tt.args.x)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("scalePoly() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_addPoly(t *testing.T) {
	a := []uint16{1, 11, 3, 4}
	b := []uint16{5, 11, 7, 8}
	z := make([]uint16, len(a))

	addPoly(f, z, a, b)

	if !reflect.DeepEqual(z, []uint16{4, 0, 4, 12}) {
		t.Error("addPoly failed")
	}
}
