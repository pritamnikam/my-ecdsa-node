// const { secp256k1 } = require("ethereum-cryptography/secp256k1");
// const { bytesToHex as toHex } = require("ethereum-cryptography/utils.js");

const ecdsa = require('./scripts/ecdsa')

const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;

app.use(cors());
app.use(express.json());

// [
//   {
//     'private key':  '4733dccdf1463726fe24a24d08173e0b35040cc16437395f28adfb45d8560af7',
//     'public key':  '03f662a4f6d9c9029459afc586c1efa06bea7b3478694d85be84f0d178f9f75fd7',
//   },

//   {
//     'private key':  '6c9411f0bb4672c9dc71923aae26131772ee96a0251204f76f01508d31333395',
//     'public key':  '03e42cd071e4f64eaec3c157ddf9b45472a821c8e01506eb7223233ea7de5a8bc1',
//   },

//   {
//     'private key':  '9e04ee6010e0a6d2127dbe3568b39b515d7a650f66e9253da875158eddeb235b',
//     'public key':  '0289570eb69f6ffbd78f3fbb027b80964af16563c23362afc45644725e31675cfb',
//   },
// ]
const balances = {
  "03f662a4f6d9c9029459afc586c1efa06bea7b3478694d85be84f0d178f9f75fd7": 100,
  "03e42cd071e4f64eaec3c157ddf9b45472a821c8e01506eb7223233ea7de5a8bc1": 50,
  "0289570eb69f6ffbd78f3fbb027b80964af16563c23362afc45644725e31675cfb": 75,
};

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const { sender, recipient, amount, signature } = req.body;

  console.log('sendAmount: ', amount);
  console.log('recipient: ', recipient);
  console.log('signature: ', signature);
  console.log('address: ', sender);

  let msg = 'Message for signing';
  const ec = new ecdsa.EDCSA();
  let signatureRecovered = JSON.parse(signature);
  const pubKeyRecovered = ec.recoverPubKey(msg, signatureRecovered);
  console.log("Recovered pubKey: ", pubKeyRecovered.encodeCompressed("hex"));
  const validSig = ec.verify(msg, signatureRecovered, pubKeyRecovered);
  console.log("Signature valid? ", validSig);
  if (!validSig) {
    res.status(400).send({ message: "Signature not matched!" });
    return;
  }

  setInitialBalance(sender);
  setInitialBalance(recipient);

  if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[recipient] += amount;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
