// Package edwards25519 provides an optimized Go implementation of a
// Twisted Edwards curve that is isomorphic to Curve25519. For details see:
// http://ed25519.cr.yp.to/.
//
// This code is based on Adam Langley's Go port of the public domain,
// "ref10" implementation of the ed25519 signing scheme in C from SUPERCOP.
// It was generalized and extended to support full kyber.Group arithmetic
// by the DEDIS lab at Yale and EPFL.
//
// Due to the field element and group arithmetic optimizations
// described in the Ed25519 paper, this implementation generally
// performs extremely well, typically comparable to native C
// implementations.  The tradeoff is that this code is completely
// specialized to a single curve.
package edwards25519

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"io"

	"github.com/dedis/student_18_dgcosi/kyber"
	"github.com/dedis/student_18_dgcosi/kyber/group/internal/marshalling"
	"fmt"
	"math/rand"
	"time"
)

type point struct {
	ge      extendedGroupElement
	varTime bool
}

func (P *point) String() string {
	var b [32]byte
	P.ge.ToBytes(&b)
	return hex.EncodeToString(b[:])
}

func (P *point) MarshalSize() int {
	return 32
}

func (P *point) MarshalBinary() ([]byte, error) {
	var b [32]byte
	P.ge.ToBytes(&b)
	return b[:], nil
}

func (P *point) UnmarshalBinary(b []byte) error {
	if !P.ge.FromBytes(b) {
		return errors.New("invalid Ed25519 curve point")
	}
	return nil
}

func (P *point) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(P, w)
}

func (P *point) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(P, r)
}

// Equality test for two Points on the same curve
func (P *point) Equal(P2 kyber.Point) bool {

	var b1, b2 [32]byte
	P.ge.ToBytes(&b1)
	P2.(*point).ge.ToBytes(&b2)
	for i := range b1 {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

// Set point to be equal to P2.
func (P *point) Set(P2 kyber.Point) kyber.Point {
	P.ge = P2.(*point).ge
	return P
}

// Set point to be equal to P2.
func (P *point) Clone() kyber.Point {
	return &point{ge: P.ge}
}

// Set to the neutral element, which is (0,1) for twisted Edwards curves.
func (P *point) Null() kyber.Point {
	P.ge.Zero()
	return P
}

// Set to the standard base point for this curve
func (P *point) Base() kyber.Point {
	P.ge = baseext
	return P
}

func (P *point) EmbedLen() int {
	// Reserve the most-significant 8 bits for pseudo-randomness.
	// Reserve the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (255 - 8 - 8) / 8
}

func (P *point) Embed(data []byte, rand cipher.Stream) kyber.Point {

	// How many bytes to embed?
	dl := P.EmbedLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		// Pick a random point, with optional embedded data
		var b [32]byte
		rand.XORKeyStream(b[:], b[:])
		if data != nil {
			b[0] = byte(dl)       // Encode length in low 8 bits
			copy(b[1:1+dl], data) // Copy in data to embed
		}
		if !P.ge.FromBytes(b[:]) { // Try to decode
			continue // invalid point, retry
		}

		// If we're using the full group,
		// we just need any point on the curve, so we're done.
		//		if c.full {
		//			return P,data[dl:]
		//		}

		// We're using the prime-order subgroup,
		// so we need to make sure the point is in that subencoding.
		// If we're not trying to embed data,
		// we can convert our point into one in the subgroup
		// simply by multiplying it by the cofactor.
		if data == nil {
			P.Mul(cofactorScalar, P) // multiply by cofactor
			if P.Equal(nullPoint) {
				continue // unlucky; try again
			}
			return P // success
		}

		// Since we need the point's y-coordinate to hold our data,
		// we must simply check if the point is in the subgroup
		// and retry point generation until it is.
		var Q point
		Q.Mul(primeOrderScalar, P)
		if Q.Equal(nullPoint) {
			return P // success
		}
		// Keep trying...
	}
}

func (P *point) Pick(rand cipher.Stream) kyber.Point {
	return P.Embed(nil, rand)
}

// Extract embedded data from a point group element
func (P *point) Data() ([]byte, error) {
	var b [32]byte
	P.ge.ToBytes(&b)
	dl := int(b[0]) // extract length byte
	if dl > P.EmbedLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[1 : 1+dl], nil
}

func (P *point) Add(P1, P2 kyber.Point) kyber.Point {
	E1 := P1.(*point)
	E2 := P2.(*point)

	var t2 cachedGroupElement
	var r completedGroupElement

	E2.ge.ToCached(&t2)
	r.Add(&E1.ge, &t2)
	r.ToExtended(&P.ge)

	return P
}

func (P *point) Sub(P1, P2 kyber.Point) kyber.Point {
	E1 := P1.(*point)
	E2 := P2.(*point)

	var t2 cachedGroupElement
	var r completedGroupElement

	E2.ge.ToCached(&t2)
	r.Sub(&E1.ge, &t2)
	r.ToExtended(&P.ge)

	return P
}

// Neg finds the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
func (P *point) Neg(A kyber.Point) kyber.Point {
	P.ge.Neg(&A.(*point).ge)
	return P
}

// Mul multiplies point p by scalar s using the repeated doubling method.
func (P *point) Mul(s kyber.Scalar, A kyber.Point) kyber.Point {

	a := &s.(*scalar).v

	if A == nil {
		geScalarMultBase(&P.ge, a)
	} else {
		if P.varTime {
			geScalarMultVartime(&P.ge, a, &A.(*point).ge)
		} else {
			geScalarMult(&P.ge, a, &A.(*point).ge)
		}
	}

	return P
}

//FIXME never used remove
// Mul multiplies point p by scalar s using the repeated doubling method.
func (P *point) DobMul(s kyber.Scalar, A kyber.Point) kyber.Point {

	a := &s.(*scalar).v

	if A == nil {
		geScalarMultBase(&P.ge, a)
	} else {
		if P.varTime {
			geScalarMultVartime(&P.ge, a, &A.(*point).ge)
		} else {
			geScalarMult(&P.ge, a, &A.(*point).ge)
		}
	}

	return P
}

// P = aA + bG
func (P *point) DoubleMul(a kyber.Scalar, A kyber.Point, b kyber.Scalar) kyber.Point {
	ax := &a.(*scalar).v
	bx := &b.(*scalar).v

	geDoubleScalarMult(&P.ge, ax, &A.(*point).ge, bx)
	return P
}






//FIXME clean up local test from lib


func newPoint()*point{
	return &point{}
}
func newScalar()*scalar{
	return &scalar{}
}
func TestMultiexpo()  {
	rand.Seed( time.Now().UnixNano())
	base := newPoint().Base()

	ar,br,hr := rand.Int63(),rand.Int63(),rand.Int63()
	//
	//ar,br,hr = 1491042876136373899, 9091797985825801395, 8382404976228838794
	//
	a,b,h := newScalar().SetInt64(ar),newScalar().SetInt64(br),newScalar().SetInt64(hr)
	//,newScalar().SetInt64(rand.Int63()),newScalar().SetInt64(rand.Int63())//newScalar().SetInt64(255+256+1024+4096)

	//X := newPoint().Mul(newScalar().SetInt64(4161312),base)

	H := newPoint().Mul(h,base)
	A := newPoint().Mul(a,base)
	B := newPoint().Mul(b,base)
	bH := newPoint().Mul(b,H)
	hB := newPoint().Mul(h,B)
	C := newPoint().Add(A,bH)
	ApB := newPoint().Add(A,B)
	DC := newPoint().DoubleMul(b,H,a)
	DApB := newPoint().DoubleMul(b,base,a)

	//proj := &projectiveGroupElement{}
	//dom := GeDoubleScalarMultVartime
	fmt.Println("ar: ", ar)
	fmt.Println("br: ",br)
	fmt.Println("hr: ",hr)
	fmt.Println("base: ", base)
	fmt.Println("H: ", H)
	fmt.Println("A: ",A)
	fmt.Println("B: ",B)
	fmt.Println("bH: ",bH)
	fmt.Println("hB: ",hB)
	fmt.Println("C=aG+bH: ",C)
	fmt.Println("DC: ",DC)
	fmt.Println("ApB: ",ApB)
	fmt.Println("DApB: ",DApB)
	fmt.Println("a,base,b: ",newPoint().DoubleMul(a,base,b))
	fmt.Println("b,base,a: ",newPoint().DoubleMul(b,base,a))
	//fmt.Println("a,H,b: ",newPoint().DoubleMul(a,H,b))
	//fmt.Println("b,H,a: ",newPoint().DoubleMul(b,H,a))
	//fmt.Println("a,X,b: ",newPoint().DoubleMul(a,X,b))
	//fmt.Println("b,X,a: ",newPoint().DoubleMul(b,X,a))


	//ext:= c.(*point).ge
	//
	//fmt.Println("a.ge: ",ext)
	//fmt.Println("a.ge.X: ",ext.X)
	//fmt.Println("a.ge.Y: ",ext.Y)
	//fmt.Println("a.ge.Z: ",ext.Z)
	//fmt.Println("a.ge.T: ",ext.T)
	//
	//pr := &projectiveGroupElement{}
	//ext.ToProjective(pr)
	//fmt.Println("a to projective A")
	//fmt.Println("A: ",pr)
	//fmt.Println("A.X: ",pr.X)
	//fmt.Println("A.Y: ",pr.Y)
	//fmt.Println("A.Z: ",pr.Z)
	//e := extendedGroupElement{}
	//e.Zero()
	//fmt.Println("E(0): ", e)
	//var cachedGi = [8]cachedGroupElement{
	//	{fieldElement{24727244, 3485679, 21838212, -13157841, -7772966, 21311296, -16463883, -871509, 5088351, -10581427}, fieldElement{-26243348, -7151119, 4254630, 3441991, 20926474, 7432598, -9815261, 14562589, -9486117, 2573989}, fieldElement{-947565, 6097708, -469190, 10704810, -8556274, -15589498, -16424464, -16608899, 14028613, -5004649}, fieldElement{-10552704, -12517169, -31816682, -3340534, 15493140, -4238420, -16181841, 15439350, -4987534, -8079536}},
	//	{fieldElement{18582421, -18807307, 9040068, -20918926, -22710211, -10230895, -9655717, -8457323, 33785525, -23171755}, fieldElement{-24207871, 7548345, 42121746, 3884368, -27093311, 14404387, 40561189, 3292159, 11295191, -7689869}, fieldElement{-7439728, 3239514, -31752154, 5246319, 9402271, -3078496, 11126314, 5028988, 13268923, -1796457}, fieldElement{23284811, -38215, -10948600, 13973676, 4945674, -13139574, 12574197, 9273482, -26639510, 12731639}},
	//	{fieldElement{20297042, 2410585, 317875, 4231603, 22871475, -12182092, -15900395, 11941674, 23826531, 19205604}, fieldElement{-40647746, 8393521, 12379763, 3269379, 25208747, -13121554, -1310055, 2131594, -16828007, 4914414}, fieldElement{-2856407, -4695433, 24277322, 8471335, -19832877, -3333731, -26214540, 2235714, 22177255, -7965929}, fieldElement{11610877, 14695051, -26752779, -10261914, 10269489, -10202701, -32619168, -843879, -30382976, 5791699}},
	//	{fieldElement{58074675, -9602380, -3895741, 9394168, 23826141, 2394262, 15465151, -10128560, -16710090, 19766335}, fieldElement{4603907, -2877048, 36299297, 20496446, 18181057, -6535050, -2064121, -2644182, 47077334, -11433665}, fieldElement{12913190, 7064048, 5778304, -6063550, -20372377, 14805632, -19843333, -15389018, -18669617, 772034}, fieldElement{-12997985, -16704036, -30260294, 1829103, -11129280, 13866523, -19506814, -9120536, 14390619, -9843984}},
	//	{fieldElement{-35522244, -4704173, -17400267, 579995, -35721245, -18832172, 14213919, 9299659, -31080789, -7512751}, fieldElement{18431652, 2240035, -1157833, 17691249, -27481271, -4026082, -23612839, -9466355, -13659069, -3191779}, fieldElement{-16600641, 4371125, -4130713, 5789099, -10088360, 7014348, 25249619, -5095628, -21164337, -14071913}, fieldElement{1975444, -6214619, 23319298, -6718776, 16136085, 16523643, 28357115, -3659996, 5591310, -5605074}},
	//	{fieldElement{50284936, 7198492, 14033517, 9795230, 42259818, -18254745, 10067000, -19034358, -26225561, -15061062}, fieldElement{-6357768, 7792488, -27044447, 10719460, -21512406, -7239393, 43228770, 10156164, 19624523, -13091044}, fieldElement{29127059, 13132465, 22987651, 13159680, -11227253, -9744827, -25517799, 9360579, -4361946, 14277915}, fieldElement{17572766, 14538621, 9831620, -6461082, -27058538, -12499804, 11080180, 9328670, 9459517, -10777327}},
	//	{fieldElement{17762050, 7546927, -8155519, -11381754, -19848353, -18366047, 41903001, 2031847, -49940474, 3448012}, fieldElement{35137622, -15433847, 26277069, 12293254, 14700619, 13293533, -17079939, -29710677, 16918696, -5007964}, fieldElement{10070252, -3967509, 27935968, 5683569, 18218733, 1029439, 18113072, 5671872, -20046655, 959170}, fieldElement{-32097219, -13709965, -23972289, -14849895, 19726124, 12687876, 28874893, -8578925, -24538705, 282881}},
	//}
		//G[ 1 ]:  {[18582421 -18807307 9040068 -20918926 -22710211 -10230895 -9655717 -8457323 33785525 -23171755] [-24207871 7548345 42121746 3884368 -27093311 14404387 40561189 3292159 11295191 -7689869] [-7439728 3239514 -31752154 5246319 9402271 -3078496 11126314 5028988 13268923 -1796457] [23284811 -38215 -10948600 13973676 4945674 -13139574 12574197 9273482 -26639510 12731639]}
		//G[ 2 ]:  {[20297042 2410585 317875 4231603 22871475 -12182092 -15900395 11941674 23826531 19205604] [-40647746 8393521 12379763 3269379 25208747 -13121554 -1310055 2131594 -16828007 4914414] [-2856407 -4695433 24277322 8471335 -19832877 -3333731 -26214540 2235714 22177255 -7965929] [11610877 14695051 -26752779 -10261914 10269489 -10202701 -32619168 -843879 -30382976 5791699]}
		//G[ 3 ]:  {[58074675 -9602380 -3895741 9394168 23826141 2394262 15465151 -10128560 -16710090 19766335] [4603907 -2877048 36299297 20496446 18181057 -6535050 -2064121 -2644182 47077334 -11433665] [12913190 7064048 5778304 -6063550 -20372377 14805632 -19843333 -15389018 -18669617 772034] [-12997985 -16704036 -30260294 1829103 -11129280 13866523 -19506814 -9120536 14390619 -9843984]}
		//G[ 4 ]:  {[-35522244 -4704173 -17400267 579995 -35721245 -18832172 14213919 9299659 -31080789 -7512751] [18431652 2240035 -1157833 17691249 -27481271 -4026082 -23612839 -9466355 -13659069 -3191779] [-16600641 4371125 -4130713 5789099 -10088360 7014348 25249619 -5095628 -21164337 -14071913] [1975444 -6214619 23319298 -6718776 16136085 16523643 28357115 -3659996 5591310 -5605074]}
		//G[ 5 ]:  {[50284936 7198492 14033517 9795230 42259818 -18254745 10067000 -19034358 -26225561 -15061062] [-6357768 7792488 -27044447 10719460 -21512406 -7239393 43228770 10156164 19624523 -13091044] [29127059 13132465 22987651 13159680 -11227253 -9744827 -25517799 9360579 -4361946 14277915] [17572766 14538621 9831620 -6461082 -27058538 -12499804 11080180 9328670 9459517 -10777327]}
		//G[ 6 ]:  {[17762050 7546927 -8155519 -11381754 -19848353 -18366047 41903001 2031847 -49940474 3448012] [35137622 -15433847 26277069 12293254 14700619 13293533 -17079939 -29710677 16918696 -5007964] [10070252 -3967509 27935968 5683569 18218733 1029439 18113072 5671872 -20046655 959170] [-32097219 -13709965 -23972289 -14849895 19726124 12687876 28874893 -8578925 -24538705 282881]}



	//var t completedGroupElement
	//var u extendedGroupElement
	//var Gst extendedGroupElement
	//Gst = baseext
	//G := &Gst
	//
	//var Gi [8]cachedGroupElement
	//G.ToCached(&Gi[0])
	//for i := 0; i < 7; i++ {
	//	t.Add(G, &Gi[i])
	//	t.ToExtended(&u)
	//	u.ToCached(&Gi[i+1])
	//}
	//for i := 0; i < 7; i++ {
	//	//fmt.Println("Gi[",i,"]: " , Gi[i])
	//	//fmt.Println("cG[",i,"]: " , cachedGi[i])
	//	fmt.Print(Gi[i] == cachedGi[i], ", ")
	//}

	//fmt.Println("cG[0]   : " , cachedGi[0])
	//fmt.Println("cached G: " , G.ToCached)
}