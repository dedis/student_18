package crypto

import (
	"github.com/dedis/kyber"
)

// GetHDirty is the discrete logarithm of H
// undermines security [break dlog] only for simulation
const hBase  =  123400
// used to encode both x and y in one scalar
// undermines security [reduce security size] only for simulation
const yDec   =  1200



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



//Compute public dg key from private dg key
func (priv *DgScalar)ComputePublic(suit kyber.Group) kyber.Point {
	G, H := suit.Point().Base(), GetH(suit)
	// pub = xG + yH
	return suit.Point().Add( suit.Point().Mul(priv.Y,H), suit.Point().Mul(priv.X, G))
}


// GetHDirty deterministically determine second generator from first one
// Due to knowing the discrete logarithm the security doesn't hold.
// Only used to encode a DoubleGenerator key to a normal key.
// WARNING: NEVER should be deployed
func GetH(suit kyber.Group) kyber.Point{
	return suit.Point().Mul(suit.Scalar().SetInt64(hBase), nil)
}

func ConvertNormalPrivateToDg( x kyber.Scalar) DgScalar {
	return DgScalar{ x.Clone(),  x.Clone().Add(x, x.Clone().SetInt64(yDec)) }
}
func ConvertDgPrivateToNormal( dg DgScalar) kyber.Scalar{
	return dg.X
}
func ConvertNormalKeyToDg(x kyber.Scalar, suite kyber.Group)DGkey{
	priv := ConvertNormalPrivateToDg(x)
	pub := priv.ComputePublic(suite)
	return DGkey{pub, priv}
}