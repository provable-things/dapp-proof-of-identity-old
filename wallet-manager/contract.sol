

contract WalletManager {

    struct eidWallet {
        uint balance;
        bytes modulus;
        uint nonce;
    }

    mapping(uint => eidWallet) eidWallets;

    bytes public CAmodulus;
    address owner;

    struct crtD { uint eid; bytes modulus; bytes crtSig; string commonName; }

    event Withdrawal(uint from, uint amount);
    event Deposit(uint to, uint amount);

    modifier onlyIfValidToEid(uint from, uint to, uint amount, uint nonce, bytes sig) {
        //We verify if eid is registered by checking if there is stored pubkey
        //if (eidWallets[from].modulus.length == 0) throw;
        //We verify if there is enough balance
        if (eidWallets[from].balance < amount) throw;
        //We verify if the transaction nonce is more than previous transaction to
        //prevent replay attack
        if (nonce <= eidWallets[from].nonce) throw;
        
        bytes32 transactionHash = sha3(from + to + amount + nonce);
        if(!rsaVerify(bytes32_to_bytes(transactionHash), eidWallets[from].modulus, 65537, sig)) throw;
        _
    }

    modifier onlyIfValidToAddress(uint from, address to, uint amount, uint nonce, bytes sig) {
         //We verify if eid is registered by checking if there is stored pubkey
        //if (eidWallets[from].modulus.length == 0) throw;
        //We verify if there is enough balance
        if (eidWallets[from].balance < amount) throw;
        //We verify if the transaction nonce is more than previous transaction to
        //prevent replay attack
        if (nonce <= eidWallets[from].nonce) throw;
        
        bytes32 transactionHash = sha3(from + uint(to) + amount + nonce);
        if(!rsaVerify(bytes32_to_bytes(transactionHash), eidWallets[from].modulus, 65537, sig)) throw;
        _
    }


    function WalletManager() {
        owner = msg.sender;
    }

    function __callback(bytes32 myid, string result) {
        if (!this.call(result)) throw;

    }

    function register(bytes cert) {
        crtD memory returnedCert = isValid(cert);
        // if empty throw;
        if (returnedCert.eid != 0) {
            eidWallets[returnedCert.eid].modulus = returnedCert.modulus;
        }
    }

    function () {
        throw;
    }

    function deposit(uint to) {
        Deposit(to, msg.value);
        eidWallets[to].balance += msg.value;
    }

    function withdrawalToEid(uint from, uint to, uint amount, uint nonce, bytes sig)
        onlyIfValidToEid(from, to, amount, nonce, sig) {
        Withdrawal(from, amount);
        Deposit(to, amount);
        eidWallets[from].balance -= amount;
        eidWallets[from].nonce += 1;
        eidWallets[to].balance += amount;
    }

    function withdrawalToAddress(uint from, address to, uint amount, uint nonce, bytes sig)
        onlyIfValidToAddress(from, to, amount, nonce, sig) {
            
        if (to.send(amount)) {
            Withdrawal(from, amount);
            eidWallets[from].nonce += 1;
            eidWallets[from].balance -= amount;
        }
    }


    function setCAmodulus(bytes _CAmodulus) public {
        //00b3e97c6c661eabfda5dc35ede44a934c3aa990a005d4a73cdcaf8652686661ffb247222a65bcd8bab5b5bf94aeec02246c6fae4accc5913846ae95deba8206c33e06ba914f7b0be0171aeefe0d1397b2d8d43afe9596b1d95409cb9883a4c9ca566b18ccf847d03d9b83c446e4c3de81dff7c6ebd65ba77b3dcba58487053963d222425f184e41a7354c627506ce375046426f87544b204dfdb627aafa1b716c134eeb9cc36c90d0b70e3b8b48250a178907d2b54654af4176209d15a6631c4ca48f08c81b3aa7cb1c9129ee186c9e81f40066f797921603011ed644614faad15508406840180bab3935e35a2d53b2c038da69cb190644239197317b5a6e9e75
        if (msg.sender != owner) throw;
        CAmodulus = _CAmodulus;
    }

    function rsaVerify(bytes msg, bytes N, uint e, bytes S) internal returns (bool){
        // sig verification
        //return RSAVerify.rsaverify(msg, N, e, S, 1);
        return true;
    }

    function copyBytes(bytes from, uint fromOffset, uint length, bytes to, uint toOffset) internal returns (bytes) {
        uint minLength = length + toOffset;

        if (to.length < minLength) {
            // Buffer too small
            throw; // Should be a better way?
        }

        // NOTE: the offset 32 is added to skip the `size` field of both bytes variables
        uint i = 32 + fromOffset;
        uint j = 32 + toOffset;

        while (i < (32 + fromOffset + length)) {
            assembly {
                let tmp := mload(add(from, i))
                mstore(add(to, j), tmp)
            }
            i += 32;
            j += 32;
        }

        return to;
    }

    function getCrtDetails(bytes _cert) internal returns (crtD){
        // asn1 cert parsing
        uint eid;
        bytes memory modulus = new bytes(32*8);
        bytes memory commonName = new bytes(26*8);
        for (uint i=0; i<_cert.length; i++){
            if (i+16 > _cert.length){
                break;
            }
            if (_cert[i] == 0x02 && _cert[i+1] == 0x01 && _cert[i+2] == 0x02 && _cert[i+3] == 0x02 && _cert[i+4] == 0x10){
                i += 5;
                assembly {
                    let tmp := mload(add(_cert, add(i, 32)))
                    eid := tmp
                }
                eid &= 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;
            }

            if (_cert[i] == 0x02 && _cert[i+1] == 0x82 && _cert[i+2] == 0x01 && _cert[i+3] == 0x01 && _cert[i+4] == 0x00){
                i += 5;
                modulus = copyBytes(_cert, i, 32*8, modulus, 0);
            }

            if (_cert[i] == 0x55 && _cert[i+1] == 0x04 && _cert[i+2] == 0x03 && _cert[i+3] == 0x0C && _cert[i+4] == 0x1A){
                i += 5;
                commonName = copyBytes(_cert, i, 26, commonName, 0);
            }

        }

        bytes memory crtSig = new bytes(32*8);
        crtSig = copyBytes(_cert, _cert.length-32*8, 32*8, crtSig, 0);
        return crtD(eid, modulus, crtSig, string(commonName));
    }


    function bytes32_to_bytes(bytes32 _in) internal returns (bytes){
        bytes memory out = new bytes(32);
        for (uint i=0; i<32; i++) out[i] = _in[i];
        return out;
    }

    function isValid(bytes _cert) internal returns (crtD){
        crtD memory mycrtD = getCrtDetails(_cert);
        crtD memory mycrtD_empty;
        if (!rsaVerify(bytes32_to_bytes(sha256(_cert)), CAmodulus, 65537, mycrtD.crtSig)) return mycrtD_empty; //bad cert
        return mycrtD;
    }

    function getBalanceOf(uint eid) constant returns(uint) {
        return eidWallets[eid].balance;
    }
    
     function getNonceOf(uint eid) constant returns(uint) {
        return eidWallets[eid].nonce;
    }

}

