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

const EPHEMERAL_TTL = process.env.EPHEMERAL_TTL || "30m"; // short-lived token TTL

// Replace this with your real OAuth/JWT verification
function verifyOAuthToken(oauthToken) {
  // TODO: validate oauthToken against provider and return { uid } or null if invalid
  if (!oauthToken) return null;
  // Mock example: treat "mockToken" as user 123 (for dev only)
  if (oauthToken === "mockToken") return { uid: "123" };
  // In real: verify JWT, extract sub/email -> uid
  return null;
}

function vaultHeaders() {
  return { "X-Vault-Token": VAULT_ADMIN_TOKEN };
}

// Create per-user transit key + policy + ephemeral token
app.post("/create", async (req, res) => {
  try {
    const { oauthToken } = req.body;
    if (!oauthToken) return res.status(400).json({ error: "Missing oauthToken" });

    // 1) verify user
    const user = verifyOAuthToken(oauthToken);
    if (!user) return res.status(401).json({ error: "Invalid oauth token" });

    const uid = user.uid;
    const keyName = `algo-user-${uid}`;
    const policyName = `sign-user-${uid}`;

    // 2) Create transit key (ed25519). If exists, Vault returns 204 or 400; handle idempotency.
    try {
      await axios.post(
        `${VAULT_ADDR}/v1/transit/keys/${encodeURIComponent(keyName)}`,
        { type: "ed25519" },
        { headers: vaultHeaders(), timeout: 10000 }
      );
    } catch (err) {
      // If key already exists, Vault may return 400; ignore that and continue.
      const status = err.response?.status;
      const data = err.response?.data;
      if (status && (status === 400 || status === 409)) {
        // key exists or conflict — continue
        console.log(`Key ${keyName} may already exist: `, data || err.message);
      } else {
        throw err;
      }
    }

    // 3) Create policy text that allows signing and reading public-key metadata
    const policyHCL = `
path "transit/sign/${keyName}" {
  capabilities = ["update"]
}

path "transit/keys/${keyName}" {
  capabilities = ["read"]
}
`.trim();

    // Write policy via sys/policies/acl/<policyName>
    // (Vault HTTP API: PUT /v1/sys/policies/acl/<name> { "policy": "<hcl>" })
    await axios.put(
      `${VAULT_ADDR}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`,
      { policy: policyHCL },
      { headers: vaultHeaders(), timeout: 10000 }
    );

    // 4) Create ephemeral token scoped to that policy
    const tokenResp = await axios.post(
      `${VAULT_ADDR}/v1/auth/token/create`,
      { policies: [policyName], ttl: EPHEMERAL_TTL },
      { headers: vaultHeaders(), timeout: 10000 }
    );

    const clientToken = tokenResp?.data?.auth?.client_token;

    // 5) Read key metadata (public key info) — read transit/keys/<keyName>
    let keyInfo = null;
    try {
      const keyInfoResp = await axios.get(
        `${VAULT_ADDR}/v1/transit/keys/${encodeURIComponent(keyName)}`,
        { headers: vaultHeaders(), timeout: 10000 }
      );
      keyInfo = keyInfoResp.data?.data || null;
    } catch (err) {
      console.warn("Could not read key metadata:", err.response?.data || err.message);
    }

    // 6) Return essential info (do NOT return admin token)
    return res.json({
      message: "user transit key & policy created",
      uid,
      keyName,
      policyName,
      ephemeralToken: clientToken, // sensitive: return only if you need client to call Vault directly
      keyInfo,
      note:
        "Treat ephemeralToken as a secret. TTL is short. Prefer exchanging via secure channel or keep it server-side."
    });
  } catch (err) {
    console.error("/create error:", err.response?.data || err.message);
    return res.status(500).json({ error: "create_failed", details: err.response?.data || err.message });
  }
});

// Example listen (if you want to run this file standalone)
// app.listen(3000, () => console.log("create-helper running on :3000"));

// Algorand client setup
const algodClient = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');

// 1️⃣ Verify OAuth token logic here (simplified mock)

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

// 💸 /mock — create, sign, and send a payment txn using Vault
app.get("/mock", async (req, res) => {
  try {
    const senderAddr = "DKD6JIA5CCTKRZJJJ25EO5GT6KMFDZYTCVCAKDEWBZYQOEU6T2UXXTIBAM";
    const receiverAddr = "JQ4DXV6ZXEQJRPRRFQDLR5WWD7WUPAELJNKP6FVSAQ4ZJNRHGBYJCKDHOY"; // test receiver
    const userId = "123"; // mock user ID for Vault key: algo-user-123

    // 1️⃣ Get transaction params from network
    const params = await algodClient.getTransactionParams().do();

    // 2️⃣ Create a simple Payment transaction (1 Algo)
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: senderAddr,
      receiver: receiverAddr,
      amount: 1_000_000, // microAlgos (1 Algo)
      note: new Uint8Array(Buffer.from("Vault Mock Payment Test")),
      suggestedParams: params,
    });

    // 3️⃣ Get bytes to sign (canonical)
    const bytesToSign = txn.bytesToSign();

    // 4️⃣ Ask Vault to sign
    const response = await axios.post(
      `${VAULT_ADDR}/v1/transit/sign/algo-user-${userId}`,
      { input: Buffer.from(bytesToSign).toString("base64") },
      { headers: { "X-Vault-Token": VAULT_TOKEN } }
    );

    const vaultSig = response.data?.data?.signature;
    if (!vaultSig) throw new Error("Vault did not return a signature");

    const sigBase64 = vaultSig.split(":").pop();
    const sigBytes = new Uint8Array(Buffer.from(sigBase64, "base64"));

    // 5️⃣ Attach signature
    const signedTxnBytes = txn.attachSignature(senderAddr, sigBytes);

    // 6️⃣ Send to network
    const txnResult = await algodClient.sendRawTransaction(signedTxnBytes).do();

    res.json({
      success: true,
      txId: txnResult.txId,
      signedTxnBase64: Buffer.from(signedTxnBytes).toString("base64"),
    });
  } catch (err) {
    console.error("Mock txn error:", err.response?.data || err.message);
    res.status(500).json({
      success: false,
      error: "Mock transaction failed",
      details: err.response?.data || err.message,
    });
  }
});


// Get wallet address endpoint
app.get("/get/:id", async (req, res) => {
  const { id } = req.params;
  
  try {
    const response = await axios.get(`${VAULT_ADDR}/v1/transit/keys/algo-user-${id}`, {
      headers: { "X-Vault-Token": VAULT_TOKEN },
    });

    const pubB64 = response.data.data.keys["1"].public_key;
    const pubBytes = new Uint8Array(Buffer.from(pubB64, "base64"));
    const walletAddress = algosdk.encodeAddress(pubBytes);
    
    res.json({ walletAddress });
  } catch (err) {
    console.error("Get address error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to get wallet address", details: err.message });
  }
});

// Root endpoint for testing
app.get("/", (req, res) => {
  res.json({ status: "Backend server is running", endpoints: ["/sign", "/get/:id"] });
});

app.listen(3000, () => console.log("Backend running on port 3000"));
