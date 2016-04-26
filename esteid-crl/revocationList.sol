import "dev.oraclize.it/api.sol";

contract CRL is usingOraclize {
    mapping (bytes32=>uint) esteIDs;
    mapping (bytes32=>uint) offsets;
    mapping (uint=>bytes32) hashes;
    
    function init(){
        oraclize_setProof(proofType_TLSNotary | proofStorage_IPFS);
        getCRL(0, 0);
    }

    function getCRL(uint when, uint offset) internal {
        bytes32 myid = oraclize_query(when, "URL", strConcat("binary(https://www.sk.ee/crls/esteid/esteid2015.crl).slice(", uint2str(offset), ",3000)"), 3000000);
        offsets[myid] = offset;
    }

    function __callback(bytes32 myid, string result, bytes proof) {
        if (msg.sender != oraclize_cbAddress()) throw;
        bytes32 hash = sha3(result);
        if (hashes[offsets[myid]] == hash) return;
        hashes[offsets[myid]] = hash;
        bytes memory crl = bytes(result);
        uint i;
        
        for (i=0; i<crl.length; i++){
            if (i+64 > crl.length){
                break;
            }
            if (crl[i] == 0x30 && crl[i+1] == 0x49 && crl[i+2] == 0x02 && crl[i+3] == 0x10){
                i += 4;
                bytes32 esteID;
                assembly {
                    let tmp := mload(add(crl, add(i, 32)))
                    esteID := tmp
                }
                esteID &= 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;
                if(crl[i+40] == 0x04 && crl[i+41] == 0x03 && crl[i+42] == 0x0A && crl[i+43] == 0x01){
                    esteIDs[esteID] = 1+uint(crl[i+44]);
                }
            }
        }
        if (crl.length == 3000) getCRL(0, offsets[myid]+i);
        else getCRL(1*day, 0);
    }
    
    function isRevocated(bytes32 esteID) constant returns(bool) {
        if(esteIDs[esteID]>0){
            return true;
        } else {
            return false;
        }
    }
    
    function revocationReason(bytes32 esteID) constant returns(uint) {
        return esteIDs[esteID]-1;
    }


    function uint2str(uint i) internal returns (string){
        if (i == 0) return "0";
        uint j = i;
        uint len;
        while (j != 0){
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len - 1;
        while (i != 0){
            bstr[k--] = byte(48 + i % 10);
            i /= 10;
        }
        return string(bstr);
    }

}
