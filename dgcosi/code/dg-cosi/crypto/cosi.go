/*
Package crypto is a temporary copy of gopkg.in/dedis/crypto.v0/cosi.

Package cosi is the Collective Signing implementation according to the paper of
Bryan Ford: http://arxiv.org/pdf/1503.08768v1.pdf .

Stages of CoSi

The CoSi-protocol has 4 stages:

1. Announcement: The leader multicasts an announcement
of the start of this round down through the spanning tree,
optionally including the statement S to be signed.

2. Commitment: Each node i picks a random scalar vi and
computes its individual commit Vi = Gvi . In a bottom-up
process, each node i waits for an aggregate commit Vˆj from
each immediate child j, if any. Node i then computes its
own aggregate commit Vˆi = Vi \prod{j ∈ Cj}{Vˆj}, where Ci is the
set of i’s immediate children. Finally, i passes Vi up to its
parent, unless i is the leader (node 0).

3. Challenge: The leader computes a collective challenge
c = H( Aggregate Commit ∥ Aggregate Public key || Message ),
then multicasts c down through the tree, along
with the statement S to be signed if it was not already
announced in phase 1.

4. Response: In a final bottom-up phase, each node i waits
to receive a partial aggregate response rˆj from each of
its immediate children j ∈ Ci. Node i now computes its
individual response ri = vi + cxi, and its partial aggregate
response rˆi = ri + \sum{j ∈ Cj}{rˆj} . Node i finally passes rˆi
up to its parent, unless i is the root.
*/
package crypto

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"
	_ "fmt"

	"github.com/dedis/student_18/dgcosi/code/kyber"
	"github.com/dedis/student_18/dgcosi/code/onet/log"
)

// CoSi is the struct that implements one round of a CoSi protocol.
// It's important to only use this struct *once per round*, and if you  try to
// use it twice, it will try to alert you if it can.
// You create a CoSi struct by giving your secret key you wish to pariticipate
// with during the CoSi protocol, and the list of public keys representing the
// list of all co-signer's public keys involved in the round.
// To use CoSi, call three different functions on it which corresponds to the last
// three phases of the protocols:
//  - (Create)Commitment: creates a new secret and its commitment. The output has to
//  be passed up to the parent in the tree.
//  - CreateChallenge: the root creates the challenge from receiving all the
//  commitments. This output must be sent down the tree using Challenge()
//  function.
//  - (Create)Response: creates and possibly aggregates all responses and the
//  output must be sent up into the tree.
// The root can then issue `Signature()` to get the final signature that can be
// verified using `VerifySignature()`.
// To handle missing signers, the signature generation will append a bitmask at
// the end of the signature with each bit index set corresponding to a missing
// cosigner. If you need to specify a missing signer, you can call
// SetMaskBit(i int, enabled bool) which will set the signer i disabled in the
// mask. The index comes from the list of public keys you give when creating the
// CoSi struct. You can also give the full mask directly with SetMask().
type CoSi struct {
	// Suite used
	suite kyber.Group
	// mask is the mask used to select which signers participated in this round
	// or not. All code regarding the mask is directly inspired from
	// github.com/bford/golang-x-crypto/ed25519/cosi code.
	*mask
	// the message being co-signed
	message []byte
	// V_hat is the aggregated commit (our own + the children's)
	aggregateCommitment kyber.Point
	// V_hat is the root aggregated commit (Every Witness)
	rootAggregateCommitment kyber.Point
	// use to compute and store aggregate public key
	aggregatePublicKey kyber.Point
	//enable aggregating public key while running commitment phase
	enablePubKeyAggregationInTree bool
	// challenge holds the challenge for this round
	challenge kyber.Scalar

	// the longterm private key CoSi will use during the response phase.
	// The private key must have its public version in the list of publics keys
	// given to CoSi.
	private DgScalar
	// Nodes public key
	publicKey kyber.Point
	// random is our own secret that we wish to commit during the commitment phase.
	random DgScalar
	// commitment is our own commitment
	commitment kyber.Point
	// response is our own computed response
	response DgScalar
	// aggregateResponses is the aggregated response from the children + our own
	aggregateResponse DgScalar
}

// NewCosi returns a new Cosi struct given the suite, the longterm secret, and
// the list of public keys. If some signers were not to be participating, you
// have to set the mask using `SetMask` method. By default, all participants are
// designated as participating. If you wish to specify which co-signers are
// participating, use NewCosiWithMask
func NewCosi(suite kyber.Group, private DgScalar, publics []kyber.Point) *CoSi {
	cosi := &CoSi{
		suite:   suite,
		private: private,
		enablePubKeyAggregationInTree: true,
	}
	cosi.publicKey = cosi.private.ComputePublic(suite)
	cosi.aggregatePublicKey =  nil
	// Start with an all-disabled participation mask, then set it correctly
	cosi.mask = newMask(suite, publics)
	return cosi
}

// CreateCommitment creates the commitment of a random secret generated from the
// given s stream. It returns the message to pass up in the tree. This is
// typically called by the leaves.
func (c *CoSi) CreateCommitment(s cipher.Stream) kyber.Point {
	c.genCommit(s)
	return c.commitment
}

// Commit creates the commitment / secret as in CreateCommitment and it also
// aggregate children commitments from the children's messages.
func (c *CoSi) Commit(s cipher.Stream, subComms []kyber.Point, subPubs []kyber.Point, ) (commit, public kyber.Point) {
	// generate our own commit
	c.genCommit(s)

	// add our own commitment to the aggregate commitment
	c.aggregateCommitment = c.suite.Point().Add(c.suite.Point().Null(), c.commitment)
	if c.enablePubKeyAggregationInTree == true{
		c.aggregatePublicKey = c.suite.Point().Add(c.suite.Point().Null(), c.publicKey)
	}
	// take the children commitments
	for _, com := range subComms {
		c.aggregateCommitment.Add(c.aggregateCommitment, com)
	}
	// take the children public key
	if c.enablePubKeyAggregationInTree == true{
		for _, pub := range subPubs {
			c.aggregatePublicKey.Add(c.aggregatePublicKey, pub)
		}

	}
	return c.aggregateCommitment, c.aggregatePublicKey

}
// sets root aggregate commit
// in root rootAggr is nil and we informs the node that it is the root
func (c *CoSi) RootAggregateCommit(rootAggr kyber.Point) kyber.Point {
	if rootAggr == nil{
		c.rootAggregateCommitment = c.aggregateCommitment
	} else{
		c.rootAggregateCommitment = rootAggr
	}
	return c.rootAggregateCommitment
}
// sets group aggregate public key aggregate
// in root rootAggr is nil and we informs the node that it is the root
func (c *CoSi) GroupAggregateKey(pub kyber.Point) kyber.Point {
	// in computation phase aggregatePublicKey is temporary and we overwrite it in the end
	if pub == nil{
		// c.aggregatePublicKey = c.aggregateCommitment

	} else{
		c.aggregatePublicKey = pub
	}
	return c.aggregatePublicKey
}
// CreateChallenge creates the challenge out of the message it has been given.
// This is typically called by Root.
func (c *CoSi) ComputeChallenge(msg []byte) (kyber.Scalar, error) {
	// H( 'sig' || Commit || AggPublic || M)
	hash := sha512.New()
	hash.Write([]byte("sig"))
	if _, err := c.rootAggregateCommitment.MarshalTo(hash); err != nil {
		return nil, err
	}
	aggPub, err := c.GetAggregatePublicKey()
	if err != nil{
		return nil, err
	}
	if _, err := aggPub.MarshalTo(hash); err != nil {
		return nil, err
	}
	hash.Write(msg)
	chalBuff := hash.Sum(nil)
	// reducing the challenge
	c.challenge = c.suite.Scalar().SetBytes(chalBuff)
	c.message = msg
	return c.challenge, nil
}

// TODO: change challenge to compute the hash
// TODO: send commit and aggregate to nodes
// Challenge keeps in memory the Challenge from the message.
//func (c *CoSi) Challenge(challenge kyber.Scalar) {
//	c.challenge = challenge
//}

// CreateResponse is called by a leaf to create its own response from the
// challenge + commitment + private key. It returns the response to send up to
// the tree.
func (c *CoSi) CreateResponse() (DgScalar, error) {
	err := c.genResponse()
	return c.response, err
}

// Response generates the response from the commitment, challenge and the
// responses of its children.
func (c *CoSi) Response(responses []DgScalar) (DgScalar, error) {
	//create your own response
	if err := c.genResponse(); err != nil {
		return DgScalar{}, err
	}
	// Add our own
	c.aggregateResponse = c.response.Clone()
	for _, resp := range responses {
		// add responses of child
		c.aggregateResponse.X.Add(c.aggregateResponse.X, resp.X)
		c.aggregateResponse.Y.Add(c.aggregateResponse.Y, resp.Y)
	}
	return c.aggregateResponse, nil
}

// Signature returns a signature using Double Generator signature
// AggregateCommit || AggregateResponse || Mask
// *NOTE*: Signature() is only intended to be called by the root since only the
// root knows the aggregate response.
func (c *CoSi) Signature() []byte {
	log.LLvl1("*********** K DG SIGN **************")
	// Sig = C || R || bitmask
	lenC := c.suite.PointLen()
	lenSigMid := lenC + c.suite.ScalarLen()
	lenSig := lenC + 2*c.suite.ScalarLen()
	sigC, err := c.rootAggregateCommitment.MarshalBinary()
	if err != nil {
		panic("Can't marshal Commitment")
	}
	sigRX, err := c.aggregateResponse.X.MarshalBinary()
	if err != nil {
		panic("Can't generate signature !")
	}
	sigRY, err := c.aggregateResponse.Y.MarshalBinary()
	if err != nil {
		panic("Can't generate signature !")
	}
	final := make([]byte, lenSig+c.mask.MaskLen())
	copy(final[:], sigC)
	copy(final[lenC:lenSigMid], sigRX)
	copy(final[lenSigMid:lenSig], sigRY)
	copy(final[lenSig:], c.mask.mask)
	return final
}

// NOTE removed for performance
// VerifyResponses verifies the response this CoSi has against the aggregated
// public key the tree is using. This is callable by any nodes in the tree,
// after it has aggregated its responses. You can enforce verification at each
// level of the tree for faster reactivity.
//TODO remove function completely
//func (c *CoSi) VerifyResponses(aggregatedPublic kyber.Point) error {
//	return nil

	//k := c.challenge
	//
	//// k * -aggPublic + s * B = k*-A + s*B
	//// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	//// <=> s*B + k*-A = r*B
	//minusPublic := c.suite.Point().Neg(aggregatedPublic)
	//kA := c.suite.Point().Mul(k, minusPublic)
	//sB := c.suite.Point().Mul(c.aggregateResponse, nil)
	//left := c.suite.Point().Add(kA, sB)
	//
	//if !left.Equal(c.aggregateCommitment) {
	//	return errors.New("recreated commitment is not equal to one given")
	//}
	//
	//return nil
//}

// VerifySignature is the method to call to verify a signature issued by a Cosi
// struct. Publics is the WHOLE list of publics keys, the mask at the end of the
// signature will take care of removing the indivual public keys that did not
// participate
func VerifySignature(suite kyber.Group, publics []kyber.Point, message, sig []byte) error{
	return errors.New("DISABLED MASK")
	lenC := suite.PointLen()
	lenSig    := lenC + 2*suite.ScalarLen()

	maskBuff := sig[lenSig:]
	mask := newMask(suite, publics)
	mask.SetMask(maskBuff)
	//aggPublic := mask.Aggregate()
	return nil
}
func VerifySignatureWithAgg(suite kyber.Group, aggPublic kyber.Point, message, sig []byte) error {
	log.Lvl2("**** Crypto verify signature with aggregate ***********")
	lenC := suite.PointLen()
	lenSigMid := lenC + suite.ScalarLen()
	lenSig    := lenC + 2*suite.ScalarLen()
	aggCommitBuff := sig[:lenC]
	aggCommit := suite.Point()
	if err := aggCommit.UnmarshalBinary(aggCommitBuff); err != nil {
		panic(err)
	}
	sigBuffX := sig[lenC:lenSigMid]
	sigIntX := suite.Scalar().SetBytes(sigBuffX)

	sigBuffY := sig[lenSigMid:lenSig]
	sigIntY := suite.Scalar().SetBytes(sigBuffY)

	aggPublicMarshal, err := aggPublic.MarshalBinary()
	if err != nil {
		return err
	}

	// H( 'sig' || Commit || AggPublic || M)
	hash := sha512.New()
	hash.Write([]byte("sig"))
	hash.Write(aggCommitBuff)
	hash.Write(aggPublicMarshal)
	hash.Write(message)
	buff := hash.Sum(nil)
	k := suite.Scalar().SetBytes(buff)

	// c = Hash(sig, g^s1*h^s2 * PK^-c, PK, m)
	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	minusPublic := suite.Point().Neg(aggPublic)
	kA := suite.Point().Mul(k, minusPublic)
	ss :=DgScalar{sigIntX, sigIntY}
	sB := ss.ComputePublic(suite)
	left := suite.Point().Add(kA, sB)

	if !left.Equal(aggCommit) {
		return errors.New("Signature invalid")
	}

	return nil
}

// AggregateResponse returns the aggregated response that this cosi has
// accumulated.
func (c *CoSi) AggregateResponse() DgScalar {
	return c.aggregateResponse
}

// GetChallenge returns the challenge that were passed down to this cosi.
func (c *CoSi) GetChallenge() kyber.Scalar {
	return c.challenge
}

// GetCommitment returns the commitment generated by this CoSi (not aggregated).
func (c *CoSi) GetCommitment() kyber.Point {
	return c.commitment
}

// GetResponse returns the individual response generated by this CoSi
func (c *CoSi) GetResponse() DgScalar {
	return c.response
}

// genCommit generates a random scalar vi and computes its individual commit
// Vi = G^vi
func (c *CoSi) genCommit(s cipher.Stream) {
	if s == nil {
		panic("s is required")
	}
	c.random = DgScalar{c.suite.Scalar().Pick(s), c.suite.Scalar().Pick(s)}
	c.commitment = c.random.ComputePublic(c.suite)
	c.aggregateCommitment = c.commitment
}

// genResponse creates the response
func (c *CoSi) genResponse() error {
	if c.private.IsEmpty() {
		return errors.New("No private key given in this cosi")
	}
	if c.random.IsEmpty() {
		return errors.New("No random scalar computed in this cosi")
	}
	if c.challenge == nil {
		return errors.New("No challenge computed in this cosi")
	}

	// resp = random - challenge * privatekey
	// i.e. ri = vi + c * xi
	respX := c.suite.Scalar().Mul(c.private.X, c.challenge)
	respY := c.suite.Scalar().Mul(c.private.Y, c.challenge)
	c.response = DgScalar{respX.Add(c.random.X, respX),respY.Add(c.random.Y, respY)}
	// no aggregation here
	c.aggregateResponse = c.response
	// paranoid protection: delete the random
	c.random = DgScalar{}
	return nil
}

func (c *CoSi)GetAggregatePublicKey() (kyber.Point , error){
	log.Lvl3("***** K DG reading GetAggregatePublicKey")
	if c.enablePubKeyAggregationInTree == false{
		return nil, errors.New("disabled enablePubKeyAggregationInTree")
	}
	return c.aggregatePublicKey, nil
}
func (c *CoSi)SetAggregatePublicKey(pub kyber.Point ){
	c.aggregatePublicKey = pub
}

// mask holds the mask utilities
type mask struct {
	mask      []byte
	publics   []kyber.Point
	aggPublic kyber.Point
	suite     kyber.Group
}

// newMask returns a new mask to use with the cosigning with all cosigners enabled
func newMask(suite kyber.Group, publics []kyber.Point) *mask {
	// Start with an all-disabled participation mask, then set it correctly
	cm := &mask{
		publics: publics,
		suite:   suite,
	}
	cm.mask = make([]byte, cm.MaskLen())
	cm.aggPublic = cm.suite.Point().Null()
	cm.allEnabled()
	return cm

}

// AllEnabled sets the pariticipation bit mask accordingly to make all
// signers participating.
func (cm *mask) allEnabled() {
	for i := range cm.mask {
		cm.mask[i] = 0xff // all disabled
	}
	cm.SetMask(make([]byte, len(cm.mask)))
}

// Set the entire participation bitmask according to the provided
// packed byte-slice interpreted in little-endian byte-order.
// That is, bits 0-7 of the first byte correspond to cosigners 0-7,
// bits 0-7 of the next byte correspond to cosigners 8-15, etc.
// Each bit is set to indicate the corresponding cosigner is disabled,
// or cleared to indicate the cosigner is enabled.
//
// If the mask provided is too short (or nil),
// SetMask conservatively interprets the bits of the missing bytes
// to be 0, or Enabled.
func (cm *mask) SetMask(mask []byte) error {
	//if cm.MaskLen() != len(mask) {
	//	err := fmt.Errorf("CosiMask.MaskLen() is %d but is given %d bytes)", cm.MaskLen(), len(mask))
	//	return err
	//}
	//masklen := len(mask)
	//for i := range cm.publics {
	//	byt := i >> 3
	//	bit := byte(1) << uint(i&7)
	//	if (byt < masklen) && (mask[byt]&bit != 0) {
	//		// Participant i disabled in new mask.
	//		if cm.mask[byt]&bit == 0 {
	//			cm.mask[byt] |= bit // disable it
	//			cm.aggPublic.Sub(cm.aggPublic, cm.publics[i])
	//		}
	//	} else {
	//		// Participant i enabled in new mask.
	//		if cm.mask[byt]&bit != 0 {
	//			cm.mask[byt] &^= bit // enable it
	//			cm.aggPublic.Add(cm.aggPublic, cm.publics[i])
	//		}
	//	}
	//}
	return nil
}

// MaskLen returns the length in bytes
// of a complete disable-mask for this cosigner list.
func (cm *mask) MaskLen() int {
	return (len(cm.publics) + 7) >> 3
}

// SetMaskBit enables or disables the mask bit for an individual cosigner.
func (cm *mask) SetMaskBit(signer int, enabled bool) {
	//if signer > len(cm.publics) {
	//	panic("SetMaskBit range out of index")
	//}
	//byt := signer >> 3
	//bit := byte(1) << uint(signer&7)
	//if !enabled {
	//	if cm.mask[byt]&bit == 0 { // was enabled
	//		cm.mask[byt] |= bit // disable it
	//		cm.aggPublic.Sub(cm.aggPublic, cm.publics[signer])
	//	}
	//} else { // enable
	//	if cm.mask[byt]&bit != 0 { // was disabled
	//		cm.mask[byt] &^= bit
	//		cm.aggPublic.Add(cm.aggPublic, cm.publics[signer])
	//	}
	//}
}

// MaskBit returns a boolean value indicating whether
// the indicated signer is enabled (true) or disabled (false)
func (cm *mask) MaskBit(signer int) bool {
	if signer > len(cm.publics) {
		panic("MaskBit given index out of range")
	}
	byt := signer >> 3
	bit := byte(1) << uint(signer&7)
	return (cm.mask[byt] & bit) != 0
}

// bytes returns the byte representation of the mask
// The bits that are left are set to a default value (1) for
// non malleability.
func (cm *mask) bytes() []byte {
	clone := make([]byte, len(cm.mask))
	for i := range clone {
		clone[i] = 0xff
	}
	copy(clone[:], cm.mask)
	return clone
}

 //Aggregate returns the aggregate public key of all *participating* signers
//func (cm *mask) Aggregate() kyber.Point {
//	return cm.aggPublic
//}
