import { secp256k1 } from "ethereum-cryptography/secp256k1.js";
import { bytesToHex as toHex } from "ethereum-cryptography/utils.js";

import sha3 from'js-sha3';

import server from "./server";
import EDCSA  from "./scripts/Edcsa"

function Wallet({ address, setAddress, balance, setBalance, privateKey, setPrivateKey, signature, setSignature }) {
  async function onChange(evt) {
    const privateKey = evt.target.value;

    const ec = new EDCSA();
    const pubKey = ec.getPublicKey(privateKey);
    const address = pubKey.encodeCompressed("hex");

    console.log(`Private key: ${privateKey}`);
    console.log("Public key :", pubKey.encode("hex").substr(2));
    console.log("Public key (compressed):", pubKey.encodeCompressed("hex"));

    console.log();

    let msg = 'Message for signing';
    let msgHash = sha3.keccak256(msg);
    const signature = ec.sign(msg, privateKey);

    console.log(`Msg: ${msg}`);
    console.log(`Msg hash: ${msgHash}`);
    console.log("Signature:", JSON.stringify(signature));

    setAddress(address);
    setPrivateKey(privateKey);
    setSignature(JSON.stringify(signature));

    if (address) {
      const {
        data: { balance },
      } = await server.get(`balance/${address}`);
      setBalance(balance);
    } else {
      setBalance(0);
    }
  }

  return (
    <div className="container wallet">
      <h1>Your Wallet</h1>

      <label>
        Your private key
        <input placeholder="Type private key" value={privateKey} onChange={onChange}></input>
      </label>

      <div>
        Wallet Address: {address}
      </div>

      <div className="balance">Balance: {balance}</div>
    </div>
  );
}

export default Wallet;
