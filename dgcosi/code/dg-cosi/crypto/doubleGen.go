package crypto

import (
	"github.com/dedis/student_18/dgcosi/code/kyber"
	"github.com/dedis/student_18/dgcosi/code/kyber/suites"
	"github.com/dedis/student_18/dgcosi/code/kyber/util/key"
)

// GetHDirty is the discrete logarithm of H
// undermines security [break dlog] only for simulation
const hBase  =  123400
// used to encode both x and y in one scalar
// undermines security [reduce security size] only for simulation
const yDec   =  1200

var baseH kyber.Point
var updateStep kyber.Point


// Pair represents a public/private double generator keypair
// We use following approach to encode a specific dg key to a
// normal key.
// This reduces the security and should only be used in simulation
// In a real usecase each server is responsible for creating and maintaining
// its key and this won't create a security issue for a deployed DG CoSi
// Normal pub = Priv.G
// DG:
// private = (x, y) = (priv, priv+yDec)
// public  = xG + yH,     H = hBase.G
type DGkey struct {
	Public  kyber.Point  // Public key Pub = xG+yH
	Private DgScalar // Private x key
}


//type DgPoint struct{
//	Public  kyber.Point   // Public key Pub = xG+yH
//}

type DgScalar struct{
	X kyber.Scalar // Private x key
	Y kyber.Scalar // Private y key
}

func (priv *DgScalar)IsEmpty() bool {
	if priv.X == nil{
		return true
	}
	return priv.Y == nil
}
func (priv *DgScalar)Clone() DgScalar{
	dg := DgScalar{priv.X.Clone(), priv.Y.Clone()}
	return dg
}



// TODO OPTIMIZE combine getH and privY into 1 Mul
//Compute public dg key from private dg key
func (priv *DgScalar)ComputePublic(suit kyber.Group) kyber.Point {
	H :=  GetH(suit)
	// G := suit.Point().Base()
	// pub = xG + yH
	return suit.Point().DoubleMul(priv.Y, H, priv.X)
	//return suit.Point().Add( suit.Point().Mul(priv.X, G), suit.Point().Mul(priv.Y,H))
}


func (priv *DgScalar)ComputePublicCHEAT(suit kyber.Group) kyber.Point {
	return suit.Point().Mul(suit.Scalar().Add(priv.X, suit.Scalar().Mul(priv.Y, suit.Scalar().SetInt64(hBase))),
		nil)
}


// GetH deterministically determine second generator from first one
// Due to knowing the discrete logarithm the security doesn't hold.
// Only used to encode a DoubleGenerator key to a normal key.
// WARNING: NEVER should be deployed
func GetH(suit kyber.Group) kyber.Point{
	if baseH == nil{
		baseH = suit.Point().Mul(suit.Scalar().SetInt64(hBase), nil)
	}
	return baseH
}
// GetStep provides the incremental update step for fast simulation (Dirty)
func GetStep(suit kyber.Group) kyber.Point{
	if updateStep == nil{
		updateStep = suit.Point().Add(GetH(suit), suit.Point().Base())
	}
	return updateStep
}

//
func NewDgKeyScalar(suite suites.Suite) (k DgScalar) {
	random := suite.RandomStream()
	if g, ok := suite.(key.Generator); ok {
		k.X = g.NewKey(random)
		k.Y = g.NewKey(random)
	} else {
		k.X = suite.Scalar().Pick(random)
		k.Y = suite.Scalar().Pick(random)
	}
	return k
}


func ConvertNormalPrivateToDg( x kyber.Scalar) DgScalar {
	return DgScalar{ x.Clone(),  x.Clone().Add(x, x.Clone().SetInt64(yDec)) }
}
func ConvertNormalKeyToDg(x kyber.Scalar, suite kyber.Group)DGkey{
	priv := ConvertNormalPrivateToDg(x)
	pub := priv.ComputePublic(suite)
	return DGkey{pub, priv}
}
func (dg *DGkey)NextKey( suite suites.Suite) {
	dg.Private.X.Add(dg.Private.X, suite.Scalar().One())
	dg.Private.Y.Add(dg.Private.Y, suite.Scalar().One())
	dg.Public.Add(GetStep(suite), dg.Public)
}