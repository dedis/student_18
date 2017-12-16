export default '{"options":{"java_package":"ch.epfl.dedis.proto","java_outer_classname":"SkipchainProto"},"nested":{"cothority":{},"ClockRequest":{"fields":{"roster":{"rule":"required","type":"Roster","id":1}}},"ClockResponse":{"fields":{"time":{"rule":"required","type":"double","id":1},"children":{"rule":"required","type":"sint32","id":2}}},"Roster":{"fields":{"id":{"type":"bytes","id":1},"list":{"rule":"repeated","type":"ServerIdentity","id":2,"options":{"packed":false}},"aggregate":{"rule":"required","type":"bytes","id":3}}},"CountRequest":{"fields":{}},"CountResponse":{"fields":{"count":{"rule":"required","type":"sint32","id":1}}},"ServerIdentity":{"fields":{"public":{"rule":"required","type":"bytes","id":1},"id":{"rule":"required","type":"bytes","id":2},"address":{"rule":"required","type":"string","id":3},"description":{"rule":"required","type":"string","id":4}}},"KeyPair":{"fields":{"public":{"rule":"required","type":"bytes","id":1},"private":{"rule":"required","type":"bytes","id":2},"publicComplete":{"type":"bytes","id":3}}},"RandomRequest":{"fields":{}},"RandomResponse":{"fields":{"r":{"rule":"required","type":"bytes","id":1},"t":{"rule":"required","type":"Transcript","id":2}},"nested":{"Transcript":{"fields":{"nodes":{"rule":"required","type":"sint32","id":1},"groups":{"rule":"required","type":"sint32","id":2},"purpose":{"rule":"required","type":"string","id":3},"time":{"rule":"required","type":"fixed64","id":4}}}}},"SignatureRequest":{"fields":{"message":{"rule":"required","type":"bytes","id":1},"roster":{"rule":"required","type":"Roster","id":2}}},"SignatureResponse":{"fields":{"hash":{"rule":"required","type":"bytes","id":1},"signature":{"rule":"required","type":"bytes","id":2}}},"Request":{"fields":{}},"Response":{"fields":{"system":{"keyType":"string","type":"Status","id":1},"server":{"rule":"required","type":"ServerIdentity","id":2}},"nested":{"Status":{"fields":{"field":{"keyType":"string","type":"string","id":1}}}}},"Device":{"fields":{"point":{"rule":"required","type":"bytes","id":1}}},"SchnorrSig":{"fields":{"challenge":{"rule":"required","type":"bytes","id":1},"response":{"rule":"required","type":"bytes","id":2}}},"ID":{"fields":{"id":{"rule":"required","type":"bytes","id":1}}},"Data":{"fields":{"threshold":{"rule":"required","type":"sint32","id":1},"device":{"keyType":"string","type":"Device","id":2},"storage":{"keyType":"string","type":"string","id":3},"votes":{"keyType":"string","type":"bytes","id":4}}},"StoreKeys":{"fields":{"type":{"rule":"required","type":"sint32","id":1},"final":{"type":"FinalStatement","id":2},"publics":{"rule":"repeated","type":"bytes","id":3},"sig":{"rule":"required","type":"bytes","id":4}}},"CreateIdentity":{"fields":{"data":{"type":"Data","id":1},"roster":{"type":"Roster","id":2},"type":{"rule":"required","type":"sint32","id":3},"public":{"rule":"required","type":"bytes","id":4},"schnorrSig":{"rule":"required","type":"bytes","id":5},"sig":{"rule":"required","type":"bytes","id":6},"nonce":{"rule":"required","type":"bytes","id":7}}},"CreateIdentityReply":{"fields":{"root":{"type":"SkipBlock","id":1},"data":{"type":"SkipBlock","id":2}}},"DataUpdate":{"fields":{"id":{"rule":"required","type":"bytes","id":1}}},"DataUpdateReply":{"fields":{"data":{"type":"Data","id":1}}},"ProposeSend":{"fields":{"id":{"rule":"required","type":"bytes","id":1},"data":{"type":"Data","id":2}}},"ProposeUpdate":{"fields":{"id":{"rule":"required","type":"bytes","id":1}}},"ProposeUpdateReply":{"fields":{"data":{"type":"Data","id":1}}},"ProposeVote":{"fields":{"id":{"rule":"required","type":"bytes","id":1},"signer":{"rule":"required","type":"string","id":2},"signature":{"type":"SchnorrSig","id":3}}},"ProposeVoteReply":{"fields":{"data":{"type":"SkipBlock","id":1}}},"PropagateIdentity":{"fields":{"tag":{"rule":"required","type":"string","id":1},"public":{"rule":"required","type":"bytes","id":2}}},"UpdateSkipBlock":{"fields":{"id":{"rule":"required","type":"ID","id":1},"latest":{"type":"SkipBlock","id":2}}},"Authenticate":{"fields":{"nonce":{"rule":"required","type":"bytes","id":1},"ctx":{"rule":"required","type":"bytes","id":2}}},"FinalStatement":{"fields":{"desc":{"rule":"required","type":"PopDesc","id":1},"attendees":{"rule":"repeated","type":"bytes","id":2},"signature":{"rule":"required","type":"bytes","id":3},"merged":{"rule":"required","type":"bool","id":4}}},"FinalStatementToml":{"fields":{"desc":{"rule":"required","type":"PopDescToml","id":1},"attendees":{"rule":"repeated","type":"string","id":2},"signature":{"rule":"required","type":"string","id":3},"merged":{"rule":"required","type":"bool","id":4}}},"PopDesc":{"fields":{"name":{"rule":"required","type":"string","id":1},"dateTime":{"rule":"required","type":"string","id":2},"location":{"rule":"required","type":"string","id":3},"roster":{"rule":"required","type":"Roster","id":4},"parties":{"type":"ShortDesc","id":5}}},"PopDescToml":{"fields":{"name":{"rule":"required","type":"string","id":1},"dateTime":{"rule":"required","type":"string","id":2},"location":{"rule":"required","type":"string","id":3},"roster":{"rule":"repeated","type":"string","id":4},"parties":{"rule":"repeated","type":"bytes","id":5}}},"ShortDesc":{"fields":{"location":{"rule":"required","type":"string","id":1},"roster":{"rule":"required","type":"Roster","id":2}}},"ShortDescToml":{"fields":{"location":{"rule":"required","type":"string","id":1},"roster":{"rule":"repeated","type":"string","id":2}}},"SkipBlock":{"fields":{"index":{"type":"int32","id":1},"height":{"type":"int32","id":2},"maxHeight":{"rule":"required","type":"int32","id":3},"baseHeight":{"rule":"required","type":"int32","id":4},"backlinks":{"type":"bytes","id":5},"verifiers":{"type":"bytes","id":6},"parent":{"type":"bytes","id":7},"genesis":{"type":"bytes","id":8},"data":{"rule":"required","type":"bytes","id":9},"roster":{"rule":"required","type":"Roster","id":10},"hash":{"type":"bytes","id":11},"forward":{"type":"BlockLink","id":12},"children":{"type":"BlockLink","id":13}}},"SkipBlockMap":{"fields":{"skipblocks":{"keyType":"string","type":"SkipBlock","id":1}}},"SkipBlockDataEntry":{"fields":{"key":{"rule":"required","type":"string","id":1},"data":{"rule":"required","type":"bytes","id":2}}},"SkipBlockData":{"fields":{"entries":{"rule":"repeated","type":"SkipBlockDataEntry","id":1,"options":{"packed":false}}}},"BlockLink":{"fields":{"hash":{"rule":"required","type":"bytes","id":1},"signature":{"rule":"required","type":"bytes","id":2}}},"GetBlock":{"fields":{"id":{"rule":"required","type":"bytes","id":1}}},"GetSingleBlock":{"fields":{"id":{"rule":"required","type":"bytes","id":1}}},"GetSingleBlockByIndex":{"fields":{"genesis":{"rule":"required","type":"bytes","id":1},"index":{"rule":"required","type":"int32","id":2}}},"GetBlockReply":{"fields":{"skipblock":{"rule":"required","type":"SkipBlock","id":1}}},"LatestBlockRequest":{"fields":{"latestId":{"rule":"required","type":"bytes","id":1}}},"LatestBlockResponse":{"fields":{"update":{"rule":"repeated","type":"SkipBlock","id":1,"options":{"packed":false}}}},"StoreSkipBlockRequest":{"fields":{"latestId":{"rule":"required","type":"bytes","id":1},"newBlock":{"rule":"required","type":"SkipBlock","id":2}}},"StoreSkipBlockResponse":{"fields":{"previous":{"rule":"required","type":"SkipBlock","id":1},"latest":{"rule":"required","type":"SkipBlock","id":2}}},"PropagateSkipBlock":{"fields":{"skipblock":{"rule":"required","type":"SkipBlock","id":1}}},"PropagateSkipBlocks":{"fields":{"skipblocks":{"rule":"repeated","type":"SkipBlock","id":1,"options":{"packed":false}}}},"ForwardSignature":{"fields":{"targetHeight":{"rule":"required","type":"int32","id":1},"previous":{"rule":"required","type":"bytes","id":2},"newest":{"rule":"required","type":"SkipBlock","id":3},"forwardLink":{"rule":"required","type":"BlockLink","id":4}}},"CheckConfig":{"fields":{"popHash":{"rule":"required","type":"bytes","id":1},"attendees":{"rule":"required","type":"bytes","id":2}}},"CheckConfigReply":{"fields":{"popStatus":{"rule":"required","type":"sint32","id":1},"popHash":{"rule":"required","type":"bytes","id":2},"attendees":{"rule":"required","type":"bytes","id":3}}},"MergeConfig":{"fields":{"final":{"rule":"required","type":"FinalStatement","id":1},"id":{"rule":"required","type":"bytes","id":2}}},"MergeConfigReply":{"fields":{"popStatus":{"rule":"required","type":"sint32","id":1},"popHash":{"rule":"required","type":"bytes","id":2},"final":{"rule":"required","type":"FinalStatement","id":3}}},"StoreConfig":{"fields":{"desc":{"rule":"required","type":"PopDesc","id":1},"signature":{"rule":"required","type":"bytes","id":2}}},"StoreConfigReply":{"fields":{"id":{"rule":"required","type":"bytes","id":1}}},"FinalizeRequest":{"fields":{"descId":{"rule":"required","type":"bytes","id":1},"attendees":{"rule":"repeated","type":"bytes","id":2},"signature":{"rule":"required","type":"bytes","id":3}}},"FinalizeResponse":{"fields":{"final":{"type":"FinalStatement","id":1}}},"FetchRequest":{"fields":{"id":{"rule":"required","type":"bytes","id":1}}},"MergeRequest":{"fields":{"id":{"rule":"required","type":"bytes","id":1},"signature":{"rule":"required","type":"bytes","id":2}}},"PinRequest":{"fields":{"pin":{"rule":"required","type":"string","id":1},"public":{"rule":"required","type":"bytes","id":2}}},"PopToken":{"fields":{"final":{"rule":"required","type":"FinalStatement","id":1},"private":{"rule":"required","type":"bytes","id":2},"public":{"rule":"required","type":"bytes","id":3}}},"PopTokenToml":{"fields":{"final":{"rule":"required","type":"FinalStatementToml","id":1},"private":{"rule":"required","type":"string","id":2},"public":{"rule":"required","type":"string","id":3}}},"GetUpdateChain":{"fields":{"latestId":{"rule":"required","type":"bytes","id":1}}},"GetUpdateChainReply":{"fields":{"update":{"rule":"repeated","type":"SkipBlock","id":1,"options":{"packed":false}}}},"GetAllSkipchains":{"fields":{}},"GetAllSkipchainsReply":{"fields":{"skipchains":{"rule":"repeated","type":"SkipBlock","id":1,"options":{"packed":false}}}}}}';