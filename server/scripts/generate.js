let sha3 = require('js-sha3');

const ecdsa = require('./ecdsa');

function main() {
    const ec = new ecdsa.EDCSA();

    const {
        privKey,
        pubKey
    } = ec.getRandomKeyPair();

    console.log(`Private key: ${privKey}`);
    console.log("Public key :", pubKey.encode("hex").substr(2));
    console.log("Public key (compressed):", pubKey.encodeCompressed("hex"));

    console.log();

    let msg = 'Message for signing';
    let msgHash = sha3.keccak256(msg);
    const signature = ec.sign(msg, privKey);

    console.log(`Msg: ${msg}`);
    console.log(`Msg hash: ${msgHash}`);
    console.log("Signature:", JSON.stringify(signature));

    const pubKeyRecovered = ec.recoverPubKey(msg, signature);
    console.log("Recovered pubKey:", pubKeyRecovered.encodeCompressed("hex"));

    let signatureRecovered = JSON.parse(JSON.stringify(signature));
    const validSig = ec.verify(msg, signatureRecovered, pubKeyRecovered);
    console.log("Signature valid?", validSig);
}

main();