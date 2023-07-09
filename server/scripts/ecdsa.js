let elliptic = require('elliptic');
let sha3 = require('js-sha3');
let ec = new elliptic.ec('secp256k1');

// ECDSA helper: secp256k1-based sign / verify / recoverPubKey
class EDCSA {
    getRandomKeyPair() {
        let keyPair = ec.genKeyPair();
        let privKey = keyPair.getPrivate("hex");
        let pubKey = keyPair.getPublic();

        return {
            privKey,
            pubKey
        };
    }

    sign(
        msg,
        privKey,    
    ) {
        let msgHash = sha3.keccak256(msg);
        let signature = ec.sign(
            msgHash,
            privKey,
            "hex",
            {canonical: true}
        );

        return signature;
    }

    recoverPubKey(
        msg,
        signature,
    ) {
        let msgHash = sha3.keccak256(msg);
        let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
        let pubKeyRecovered = ec.recoverPubKey(
                hexToDecimal(msgHash), 
                signature, 
                signature.recoveryParam, 
                "hex"
            );
        return pubKeyRecovered;
    }

    verify(
        msg,
        signature,
        pubKey,
    ) {
        let msgHash = sha3.keccak256(msg);
        let validSig = ec.verify(
            msgHash,
            signature, 
            pubKey,
        );
        return validSig;
    }
}

module.exports = {
    EDCSA,
};