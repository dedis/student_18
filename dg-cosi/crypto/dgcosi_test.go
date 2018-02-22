package crypto

import (
	"testing"
	"github.com/dedis/kyber/suites"
	"github.com/dedis/kyber"
	"fmt"
)

var tSuite = suites.MustFind("Ed25519")
var msg = []byte("Dg CoSi works.")

// test signature for only one node (no cosi structure)
func TestDgCosiStandalone(t *testing.T) {
	fmt.Println("running TestDgCosiStandalone")
	rootScaler := NewDgKeyScalar(tSuite)
	rootPoint := rootScaler.ComputePublic(tSuite)
	rootCosi := NewCosi(tSuite, rootScaler,[]kyber.Point{rootPoint})

	com := rootCosi.Commit(tSuite.RandomStream(), nil)
	fmt.Println("Commit: ", com)
	c, err := rootCosi.ComputeChallenge(msg)
	fmt.Println("ComputeChallenge: ", c, err)
	resp, err := rootCosi.Response(nil)
	fmt.Println("Response: ", resp, err)
	signature := rootCosi.Signature()
	fmt.Println("Signature: ", signature)

	//manual fail test no need for repetition
	//msg = []byte("Dg CoSi doesn't works.")
	//rootPoint.Add(tSuite.Point().Base(), rootPoint)
	//signature[2] += 2
	//signature[len(signature)-2] += 2

	accept := VerifySignature(tSuite, []kyber.Point{rootPoint},msg, signature)
	fmt.Println("VerifySignature: ", accept)
	if accept != nil{
		t.Fail()
	}

}

// test signature for few manual nodes nodes (no cosi structure)
func TestDgCosiManualProtocol(t *testing.T) {
	fmt.Println("running TestDgCosiManualProtocol")
	sn := 5
	keys := make([]DgScalar, sn)
	pubs := make([]kyber.Point, sn)
	cosis:= make([]*CoSi, sn)
	for i:=0; i < sn; i++{
		keys[i] = NewDgKeyScalar(tSuite)
		pubs[i] = keys[i].ComputePublic(tSuite)
	}
	for i:=0; i < sn; i++ {
		cosis[i] = NewCosi(tSuite, keys[i], pubs)
	}
	root := cosis[0]

	fmt.Println("cosis generated")

	comlist := make([]kyber.Point, sn)
	for i:=1; i < sn; i++ {
		comlist[i] = cosis[i].Commit(tSuite.RandomStream(), nil)
	}
	comagg := root.Commit(tSuite.RandomStream(), comlist[1:])
	fmt.Println("Commit: ", comagg)


	c, err := root.ComputeChallenge(msg)
	for i:=1; i < sn; i++ {
		cosis[i].Challenge(c)
	}
	fmt.Println("ComputeChallenge: ", c, err)

	resplist := make([]DgScalar, sn)
	for i:=1; i < sn; i++ {
		resplist[i],err = cosis[i].Response(nil)
		if err != nil{
			fmt.Println("Response children failed: ", resplist[i-1], err)
			t.Fail()
		}
	}
	resp, err := root.Response(resplist[1:])
	fmt.Println("Response: ", resp, err)


	signature := root.Signature()
	fmt.Println("Signature: ", signature)

	//manual fail test no need for repetition
	//msg = []byte("Dg CoSi doesn't works.")
	//rootPoint.Add(tSuite.Point().Base(), rootPoint)
	//signature[2] += 2
	//signature[len(signature)-2] += 2

	accept := VerifySignature(tSuite, pubs,msg, signature)
	fmt.Println("VerifySignature: ", accept)
	if accept != nil{
		t.Fail()
	}

}
