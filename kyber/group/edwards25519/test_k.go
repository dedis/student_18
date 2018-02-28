package edwards25519

//import (
//	"fmt"
//)
//
//func newPoint()*point{
//	return &point{}
//}
//func newScalar()*scalar{
//	return &scalar{}
//}
//
//func TestMultiexpo()  {
//	base := newPoint().Base()
//	a := newPoint().Mul(newScalar().SetInt64(11),base)
//	h := newPoint().Mul(newScalar().SetInt64(17),base)
//	b := newPoint().Mul(newScalar().SetInt64(13),h)
//	c := newPoint().Add(a,b)
//
//	//proj := &projectiveGroupElement{}
//	//dom := GeDoubleScalarMultVartime
//	fmt.Println("h: ", h)
//	fmt.Println("a: ",a)
//	fmt.Println("b: ",b)
//	fmt.Println("c: ",c)
//
//	fmt.Println(a.)
//
//}
//// GeDoubleScalarMultVartime sets r = a*A + b*B
//// where a = a[0]+256*a[1]+...+256^31 a[31].
//// and b = b[0]+256*b[1]+...+256^31 b[31].
//// B is the Ed25519 base point (x,4/5) with x positive.
//func GeDoubleScalarMultVartime(r *projectiveGroupElement, a *[32]byte, A *extendedGroupElement, b *[32]byte) {
//	var aSlide, bSlide [256]int8
//	var Ai [8]cachedGroupElement // A,3A,5A,7A,9A,11A,13A,15A
//	var t completedGroupElement
//	var u, A2 extendedGroupElement
//	var i int
//
//	slide(&aSlide, a)
//	slide(&bSlide, b)
//
//	A.ToCached(&Ai[0])
//	A.Double(&t)
//	t.ToExtended(&A2)
//
//	for i := 0; i < 7; i++ {
//		geAdd(&t, &A2, &Ai[i])
//		t.ToExtended(&u)
//		u.ToCached(&Ai[i+1])
//	}
//
//	r.Zero()
//
//	for i = 255; i >= 0; i-- {
//		if aSlide[i] != 0 || bSlide[i] != 0 {
//			break
//		}
//	}
//
//	for ; i >= 0; i-- {
//		r.Double(&t)
//
//		if aSlide[i] > 0 {
//			t.ToExtended(&u)
//			geAdd(&t, &u, &Ai[aSlide[i]/2])
//		} else if aSlide[i] < 0 {
//			t.ToExtended(&u)
//			geSub(&t, &u, &Ai[(-aSlide[i])/2])
//		}
//
//		if bSlide[i] > 0 {
//			t.ToExtended(&u)
//			geMixedAdd(&t, &u, &bi[bSlide[i]/2])
//		} else if bSlide[i] < 0 {
//			t.ToExtended(&u)
//			geMixedSub(&t, &u, &bi[(-bSlide[i])/2])
//		}
//
//		t.ToProjective(r)
//	}
//}
