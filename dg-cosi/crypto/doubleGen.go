package crypto

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/suites"
)

// GetHDirty is the discrete logarithm of H
// undermines security [break dlog] only for simulation
const hBase  =  12345
// used to encode both x and y in one scalar
// undermines security [reduce security size] only for simulation
const yDec   =  123



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
	Public  DgPublic   // Public key Pub = xG+yH
	Private DgPrivate  // Private x key
}

type DgPublic struct{
	Public  kyber.Point   // Public key Pub = xG+yH
}

type DgPrivate struct{
	X kyber.Scalar // Private x key
	Y kyber.Scalar // Private y key
}


//Compute public dg key from private dg key
func (priv *DgPrivate)ComputePublic(suit suites.Suite) DgPublic{
	G, H := suit.Point().Base(), GetH(suit)
	pub := DgPublic{}
	// pub = xG + yH
	pub.Public = suit.Point().Add( suit.Point().Mul(priv.Y,H), suit.Point().Mul(priv.X, G))
	return pub
}


// GetHDirty deterministically determine second generator from first one
// Due to knowing the discrete logarithm the security doesn't hold.
// Only used to encode a DoubleGenerator key to a normal key.
// WARNING: NEVER should be deployed
func GetH(suit suites.Suite) kyber.Point{
	return suit.Point().Mul(suit.Scalar().SetInt64(hBase), nil)
}

func ConvertNormalPrivateToDg( x kyber.Scalar) DgPrivate{
	priv := DgPrivate{}
	priv.X = x.Clone()
	priv.Y = x.Add(x, x.Clone().SetInt64(yDec))
	return priv
}
func ConvertDgPrivateToNormal( dg DgPrivate) kyber.Scalar{
	return dg.X
}
