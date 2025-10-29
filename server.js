import express from "express";
import axios from "axios";
import * as algosdk from "algosdk";

const app = express();

// Simple JSON middleware without body-parser conflicts
app.use((req, res, next) => {
  if (req.method === 'POST') {
    let data = '';
    req.on('data', chunk => {
      data += chunk.toString();
    });
    req.on('end', () => {
      try {
        req.body = JSON.parse(data || '{}');
        next();
      } catch (err) {
        res.status(400).json({ error: 'Invalid JSON' });
      }
    });
  } else {
    next();
  }
});

const VAULT_ADDR = "http://127.0.0.1:8200";
const VAULT_TOKEN = "root";

// Algorand client setup
const algodClient = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');

// 1️⃣ Verify OAuth token logic here (simplified mock)
function verifyOAuthToken(token) {
  // TODO: Verify JWT via Google/Privy etc.
  return { uid: "123" }; // Example user
}

// 2️⃣ Sign endpoint
// 2️⃣ Sign endpoint (fixed)
// improved /sign handler with algosdk export fallbacks
app.post("/sign", async (req, res) => {
  const { txn, oauthToken } = req.body;
  const user = verifyOAuthToken(oauthToken);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  try {
    // decode input (same assumption as before)
    const decoded = Buffer.from(txn, "base64").toString();
    const txnObj = JSON.parse(decoded).txn;

    // ---- create a Transaction instance (try several fallbacks) ----
    let txnInstance = null;

    // 1) prefer direct top-level helper if present
    if (typeof algosdk.instantiateTxnIfNeeded === "function") {
      txnInstance = algosdk.instantiateTxnIfNeeded(txnObj);
    }
    // 2) try namespaced module (some builds export under .transaction or .txnBuilder)
    else if (algosdk.transaction && typeof algosdk.transaction.instantiateTxnIfNeeded === "function") {
      txnInstance = algosdk.transaction.instantiateTxnIfNeeded(txnObj);
    }
    else if (algosdk.txnBuilder && typeof algosdk.txnBuilder.instantiateTxnIfNeeded === "function") {
      txnInstance = algosdk.txnBuilder.instantiateTxnIfNeeded(txnObj);
    }
    // 3) try Transaction.from_obj_for_encoding (constructor factory)
    else if (algosdk.Transaction && typeof algosdk.Transaction.from_obj_for_encoding === "function") {
      txnInstance = algosdk.Transaction.from_obj_for_encoding(txnObj);
    }
    // 4) lastly, try the constructor (works for many versions)
    else if (typeof algosdk.Transaction === "function") {
      txnInstance = new algosdk.Transaction(txnObj);
    }
    else {
      throw new Error("Unable to construct Transaction: algosdk API shape not recognized. Check your algosdk version.");
    }

    // ---- get canonical bytes to sign ----
    if (typeof txnInstance.bytesToSign !== "function") {
      throw new Error("Transaction instance does not have bytesToSign(); incompatible algosdk API.");
    }
    const bytesToSign = txnInstance.bytesToSign(); // Uint8Array

    // ---- call Vault (Transit sign) ----
    const payload = { input: Buffer.from(bytesToSign).toString("base64") };
    const response = await axios.post(
      `${VAULT_ADDR}/v1/transit/sign/algo-user-${user.uid}`,
      payload,
      { headers: { "X-Vault-Token": VAULT_TOKEN } }
    );

    const vaultSig = response.data?.data?.signature;
    if (!vaultSig) throw new Error("No signature returned from Vault");

    // vault returns "vault:v1:<BASE64>" — keep last section
    const sigBase64 = vaultSig.split(":").pop();
    const sigBytes = Buffer.from(sigBase64, "base64"); // Node Buffer (Uint8Array-compatible)

    // ---- attach signature ----
    if (typeof txnInstance.attachSignature === "function") {
      // attachSignature expects (addr, sig) and returns the signed msgpack bytes (Uint8Array)
      // use txnInstance.from as the address to attach the signature to
      const signedTxnBytes = txnInstance.attachSignature(txnInstance.from, new Uint8Array(sigBytes));

      // optional: local verify (if algosdk provides verifyBytes)
      if (typeof algosdk.verifyBytes === "function") {
        try {
          const ok = algosdk.verifyBytes(bytesToSign, new Uint8Array(sigBytes), txnInstance.from);
          if (!ok) console.warn("Local signature verification failed (verifyBytes returned false).");
        } catch (e) {
          console.warn("verifyBytes check threw:", e.message || e);
        }
      }

      // submit the signed bytes to algod
      const txnResult = await algodClient.sendRawTransaction(signedTxnBytes).do();

      res.json({
        txId: txnResult.txId,
        signedBytesBase64: Buffer.from(signedTxnBytes).toString("base64"),
      });
      return;
    } else if (typeof algosdk.encodeObj === "function") {
      // fallback: build signed txn object and msgpack-encode it
      const signedTxnObj = { txn: txnInstance.get_obj_for_encoding ? txnInstance.get_obj_for_encoding() : txnObj, sig: sigBytes };
      const signedBytes = algosdk.encodeObj(signedTxnObj); // msgpack
      const txnResult = await algodClient.sendRawTransaction(signedBytes).do();

      res.json({
        txId: txnResult.txId,
        signedBytesBase64: Buffer.from(signedBytes).toString("base64"),
      });
      return;
    } else {
      throw new Error("No method available to attach signature (attachSignature or algosdk.encodeObj missing).");
    }
  } catch (err) {
    console.error("Signing failed:", err.response?.data || err.message || err);
    res.status(500).json({ error: "Signing failed", details: (err.response?.data || err.message || err).toString() });
  }
});



// Root endpoint for testing
app.get("/", (req, res) => {
  res.json({ status: "Backend server is running", endpoints: ["/sign"] });
});

app.listen(3000, () => console.log("Backend running on port 3000"));
