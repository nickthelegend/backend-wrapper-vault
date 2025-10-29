import express from "express";
import axios from "axios";
import * as algosdk from "algosdk";

// Environment variables
const VAULT_ADDR = process.env.VAULT_ADDR || 'http://localhost:8200';
const VAULT_TOKEN = process.env.VAULT_TOKEN || "root";
const VAULT_ADMIN_TOKEN = process.env.VAULT_ADMIN_TOKEN || "root";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '999958886943-nc6u54rh7lbn6dikpt1k708r46pl1rrp.apps.googleusercontent.com';

console.log('🔧 Environment Config:');
console.log('VAULT_ADDR:', VAULT_ADDR);
console.log('VAULT_TOKEN:', VAULT_TOKEN ? '***SET***' : 'NOT SET');
console.log('VAULT_ADMIN_TOKEN:', VAULT_ADMIN_TOKEN ? '***SET***' : 'NOT SET');

if (!VAULT_TOKEN) {
  console.error('VAULT_TOKEN environment variable is required');
  process.exit(1);
}

const app = express();

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Simple JSON middleware without body-parser conflicts
app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.url}`);
  if (req.method === 'POST') {
    let data = '';
    req.on('data', chunk => {
      data += chunk.toString();
    });
    req.on('end', () => {
      try {
        req.body = JSON.parse(data || '{}');
        console.log('📦 Request body:', JSON.stringify(req.body, null, 2));
        next();
      } catch (err) {
        console.error('❌ Invalid JSON:', err.message);
        res.status(400).json({ error: 'Invalid JSON' });
      }
    });
  } else {
    next();
  }
});

const EPHEMERAL_TTL = process.env.EPHEMERAL_TTL || "30m"; // short-lived token TTL

// Google OAuth token verification
async function verifyOAuthToken(oauthToken) {
  console.log('🔐 Verifying OAuth token:', oauthToken ? oauthToken.substring(0, 20) + '...' : 'NONE');
  
  if (!oauthToken) {
    console.log('❌ No OAuth token provided');
    return null;
  }
  
  // Mock token for testing
  if (oauthToken === "mockToken") {
    console.log('✅ Mock token verified for user 123');
    return { uid: "123" };
  }
  
  try {
    // Verify Google OAuth token
    const response = await axios.get(`https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${oauthToken}`);
    const tokenInfo = response.data;
    
    console.log('📋 Google token info:', {
      audience: tokenInfo.audience,
      user_id: tokenInfo.user_id,
      email: tokenInfo.email,
      verified_email: tokenInfo.verified_email
    });
    
    // Verify the token is for our app
    if (tokenInfo.audience !== GOOGLE_CLIENT_ID) {
      console.log('❌ Token audience mismatch');
      return null;
    }
    
    // Return user info with Google user ID as uid
    console.log('✅ Google token verified for user:', tokenInfo.user_id);
    return { 
      uid: tokenInfo.user_id,
      email: tokenInfo.email,
      verified_email: tokenInfo.verified_email
    };
    
  } catch (err) {
    console.log('❌ Google token verification failed:', err.response?.data || err.message);
    return null;
  }
}

function vaultHeaders() {
  return { "X-Vault-Token": VAULT_ADMIN_TOKEN };
}

// Create per-user transit key + policy + ephemeral token
app.post("/create", async (req, res) => {
  console.log('🚀 /create endpoint called');
  try {
    const { oauthToken } = req.body;
    console.log('📋 Create request data:', { oauthToken: oauthToken ? '***PROVIDED***' : 'MISSING' });
    
    if (!oauthToken) return res.status(400).json({ error: "Missing oauthToken" });

    // 1) verify user
    const user = await verifyOAuthToken(oauthToken);
    if (!user) return res.status(401).json({ error: "Invalid oauth token" });

    const uid = user.uid;
    const keyName = `algo-user-${uid}`;
    const policyName = `sign-user-${uid}`;
    
    console.log('👤 User verified:', { uid, keyName, policyName });

    // 2) Create transit key (ed25519). If exists, Vault returns 204 or 400; handle idempotency.
    console.log('🔑 Creating transit key:', keyName);
    try {
      const keyUrl = `${VAULT_ADDR}/v1/transit/keys/${encodeURIComponent(keyName)}`;
      const keyPayload = { type: "ed25519" };
      console.log('📡 Key creation request:', { url: keyUrl, payload: keyPayload });
      
      const keyResp = await axios.post(keyUrl, keyPayload, { headers: vaultHeaders(), timeout: 10000 });
      console.log('✅ Key created successfully:', keyResp.status);
    } catch (err) {
      // If key already exists, Vault may return 400; ignore that and continue.
      const status = err.response?.status;
      const data = err.response?.data;
      console.log('⚠️ Key creation error:', { status, data: data || err.message });
      if (status && (status === 400 || status === 409)) {
        // key exists or conflict — continue
        console.log(`✅ Key ${keyName} already exists, continuing...`);
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
    console.log('📜 Creating policy:', policyName);
    console.log('📝 Policy HCL:', policyHCL);
    
    const policyUrl = `${VAULT_ADDR}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`;
    const policyPayload = { policy: policyHCL };
    console.log('📡 Policy creation request:', { url: policyUrl });
    
    const policyResp = await axios.put(policyUrl, policyPayload, { headers: vaultHeaders(), timeout: 10000 });
    console.log('✅ Policy created:', policyResp.status);

    // 4) Create ephemeral token scoped to that policy
    console.log('🎫 Creating ephemeral token for policy:', policyName);
    const tokenUrl = `${VAULT_ADDR}/v1/auth/token/create`;
    const tokenPayload = { policies: [policyName], ttl: EPHEMERAL_TTL };
    console.log('📡 Token creation request:', { url: tokenUrl, payload: tokenPayload });
    
    const tokenResp = await axios.post(tokenUrl, tokenPayload, { headers: vaultHeaders(), timeout: 10000 });
    console.log('📋 Token response:', tokenResp.data);
    
    const clientToken = tokenResp?.data?.auth?.client_token;
    console.log('🎫 Client token:', clientToken ? '***CREATED***' : 'NOT CREATED');

    // 5) Read key metadata (public key info) — read transit/keys/<keyName>
    console.log('📖 Reading key metadata for:', keyName);
    let keyInfo = null;
    try {
      const keyInfoUrl = `${VAULT_ADDR}/v1/transit/keys/${encodeURIComponent(keyName)}`;
      console.log('📡 Key info request:', keyInfoUrl);
      
      const keyInfoResp = await axios.get(keyInfoUrl, { headers: vaultHeaders(), timeout: 10000 });
      keyInfo = keyInfoResp.data?.data || null;
      console.log('📋 Key info retrieved:', keyInfo ? 'SUCCESS' : 'NO DATA');
    } catch (err) {
      console.warn("⚠️ Could not read key metadata:", err.response?.data || err.message);
    }

    // 6) Return essential info (do NOT return admin token)
    const response = {
      message: "user transit key & policy created",
      uid,
      keyName,
      policyName,
      ephemeralToken: clientToken, // sensitive: return only if you need client to call Vault directly
      keyInfo,
      note:
        "Treat ephemeralToken as a secret. TTL is short. Prefer exchanging via secure channel or keep it server-side."
    };
    console.log('✅ /create success response:', { ...response, ephemeralToken: response.ephemeralToken ? '***HIDDEN***' : 'NONE' });
    return res.json(response);
  } catch (err) {
    console.error("❌ /create error:", {
      message: err.message,
      status: err.response?.status,
      data: err.response?.data,
      stack: err.stack
    });
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
  console.log('🚀 /sign endpoint called');
  const { txn, oauthToken } = req.body;
  console.log('📋 Sign request data:', { 
    txn: txn ? `${txn.substring(0, 50)}...` : 'MISSING',
    oauthToken: oauthToken ? '***PROVIDED***' : 'MISSING'
  });
  
  const user = await verifyOAuthToken(oauthToken);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  try {
    // decode input (same assumption as before)
    console.log('🔓 Decoding transaction...');
    const decoded = Buffer.from(txn, "base64").toString();
    console.log('📋 Decoded transaction:', decoded.substring(0, 200) + '...');
    const txnObj = JSON.parse(decoded).txn;
    console.log('📦 Transaction object:', JSON.stringify(txnObj, null, 2));

    // ---- create a Transaction instance (try several fallbacks) ----
    console.log('🔨 Creating transaction instance...');
    let txnInstance = null;

    // 1) prefer direct top-level helper if present
    if (typeof algosdk.instantiateTxnIfNeeded === "function") {
      console.log('✅ Using algosdk.instantiateTxnIfNeeded');
      txnInstance = algosdk.instantiateTxnIfNeeded(txnObj);
    }
    // 2) try namespaced module (some builds export under .transaction or .txnBuilder)
    else if (algosdk.transaction && typeof algosdk.transaction.instantiateTxnIfNeeded === "function") {
      console.log('✅ Using algosdk.transaction.instantiateTxnIfNeeded');
      txnInstance = algosdk.transaction.instantiateTxnIfNeeded(txnObj);
    }
    else if (algosdk.txnBuilder && typeof algosdk.txnBuilder.instantiateTxnIfNeeded === "function") {
      console.log('✅ Using algosdk.txnBuilder.instantiateTxnIfNeeded');
      txnInstance = algosdk.txnBuilder.instantiateTxnIfNeeded(txnObj);
    }
    // 3) try Transaction.from_obj_for_encoding (constructor factory)
    else if (algosdk.Transaction && typeof algosdk.Transaction.from_obj_for_encoding === "function") {
      console.log('✅ Using algosdk.Transaction.from_obj_for_encoding');
      txnInstance = algosdk.Transaction.from_obj_for_encoding(txnObj);
    }
    // 4) lastly, try the constructor (works for many versions)
    else if (typeof algosdk.Transaction === "function") {
      console.log('✅ Using algosdk.Transaction constructor');
      txnInstance = new algosdk.Transaction(txnObj);
    }
    else {
      throw new Error("Unable to construct Transaction: algosdk API shape not recognized. Check your algosdk version.");
    }
    console.log('✅ Transaction instance created');

    // ---- get canonical bytes to sign ----
    console.log('📝 Getting bytes to sign...');
    if (typeof txnInstance.bytesToSign !== "function") {
      throw new Error("Transaction instance does not have bytesToSign(); incompatible algosdk API.");
    }
    const bytesToSign = txnInstance.bytesToSign(); // Uint8Array
    console.log('📋 Bytes to sign length:', bytesToSign.length);

    // ---- call Vault (Transit sign) ----
    console.log('🔐 Calling Vault to sign...');
    const payload = { input: Buffer.from(bytesToSign).toString("base64") };
    const signUrl = `${VAULT_ADDR}/v1/transit/sign/algo-user-${user.uid}`;
    console.log('📡 Vault sign request:', { url: signUrl, payloadLength: payload.input.length });
    
    const response = await axios.post(signUrl, payload, { headers: { "X-Vault-Token": VAULT_TOKEN } });
    console.log('📋 Vault sign response:', response.data);

    const vaultSig = response.data?.data?.signature;
    console.log('🔏 Vault signature:', vaultSig);
    if (!vaultSig) throw new Error("No signature returned from Vault");

    // vault returns "vault:v1:<BASE64>" — keep last section
    const sigBase64 = vaultSig.split(":").pop();
    console.log('📋 Signature base64 length:', sigBase64.length);
    const sigBytes = Buffer.from(sigBase64, "base64"); // Node Buffer (Uint8Array-compatible)
    console.log('📋 Signature bytes length:', sigBytes.length);

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
      console.log('📤 Submitting to Algorand network...');
      const txnResult = await algodClient.sendRawTransaction(signedTxnBytes).do();
      console.log('✅ Transaction submitted:', txnResult);

      const result = {
        txId: txnResult.txId,
        signedBytesBase64: Buffer.from(signedTxnBytes).toString("base64"),
      };
      console.log('✅ /sign success response:', result);
      res.json(result);
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
    console.error("❌ Signing failed:", {
      message: err.message,
      status: err.response?.status,
      data: err.response?.data,
      stack: err.stack
    });
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


// Sign and execute transaction endpoint
app.post("/sign-txn", async (req, res) => {
  console.log('🚀 /sign-txn endpoint called');
  try {
    const { txnBytes, senderAddr, oauthToken } = req.body;
    console.log('📋 Sign-txn request:', { 
      txnBytes: txnBytes ? 'PROVIDED' : 'MISSING',
      senderAddr,
      oauthToken: oauthToken ? '***PROVIDED***' : 'MISSING'
    });
    
    // Verify user
    const user = await verifyOAuthToken(oauthToken);
    if (!user) return res.status(401).json({ error: "Invalid oauth token" });

    const userId = user.uid;
    console.log('👤 User verified:', userId);

    // Decode transaction bytes to get bytesToSign
    const txnBytesBuffer = Buffer.from(txnBytes, 'base64');
    const txnObj = algosdk.decodeUnsignedTransaction(txnBytesBuffer);
    const bytesToSign = txnObj.bytesToSign();
    console.log('📝 Bytes to sign length:', bytesToSign.length);

    // Ask Vault to sign
    console.log('🔐 Calling Vault to sign...');
    const response = await axios.post(
      `${VAULT_ADDR}/v1/transit/sign/algo-user-${userId}`,
      { input: Buffer.from(bytesToSign).toString('base64') },
      { headers: { "X-Vault-Token": VAULT_ADMIN_TOKEN } }
    );

    const vaultSig = response.data?.data?.signature;
    console.log('🔏 Vault signature:', vaultSig);
    if (!vaultSig) throw new Error("Vault did not return a signature");

    const sigBase64 = vaultSig.split(":").pop();
    const sigBytes = new Uint8Array(Buffer.from(sigBase64, "base64"));
    console.log('📋 Signature bytes length:', sigBytes.length);

    // Attach signature and create signed transaction
    const signedTxnBytes = txnObj.attachSignature(senderAddr, sigBytes);
    console.log('✅ Transaction signed');

    // Execute transaction on Algorand network
    console.log('📤 Submitting to Algorand network...');
    const txnResult = await algodClient.sendRawTransaction(signedTxnBytes).do();
    console.log('✅ Transaction executed:', txnResult);

    const result = {
      success: true,
      txId: txnResult.txId,
      signature: Buffer.from(sigBytes).toString("base64"),
      signedTxnBytes: Buffer.from(signedTxnBytes).toString("base64")
    };
    console.log('✅ /sign-txn success response:', result);
    res.json(result);
  } catch (err) {
    console.error("❌ Sign-txn error:", {
      message: err.message,
      status: err.response?.status,
      data: err.response?.data,
      stack: err.stack
    });
    res.status(500).json({
      success: false,
      error: "Transaction signing/execution failed",
      details: err.response?.data || err.message,
    });
  }
});
// Get wallet address endpoint
app.get("/get/:id", async (req, res) => {
  console.log('🚀 /get/:id endpoint called');
  const { id } = req.params;
  console.log('📋 Get address request for user ID:', id);
  
  try {
    const keyUrl = `${VAULT_ADDR}/v1/transit/keys/algo-user-${id}`;
    console.log('📡 Vault key request:', keyUrl);
    
    const response = await axios.get(keyUrl, {
      headers: { "X-Vault-Token": VAULT_ADMIN_TOKEN },
    });
    console.log('📋 Vault key response:', response.data);

    const pubB64 = response.data.data.keys["1"].public_key;
    console.log('🔑 Public key base64:', pubB64);
    
    const pubBytes = new Uint8Array(Buffer.from(pubB64, "base64"));
    console.log('📋 Public key bytes length:', pubBytes.length);
    
    const walletAddress = algosdk.encodeAddress(pubBytes);
    console.log('🏠 Wallet address:', walletAddress);
    
    const result = { walletAddress };
    console.log('✅ /get success response:', result);
    res.json(result);
  } catch (err) {
    console.error("❌ Get address error:", {
      message: err.message,
      status: err.response?.status,
      data: err.response?.data,
      stack: err.stack
    });
    
    if (err.response?.status === 404) {
      res.status(404).json({ 
        error: "Key not found", 
        message: `No Vault key found for user ID: ${id}. Please create a wallet first using the /create endpoint.`,
        keyName: `algo-user-${id}`
      });
    } else {
      res.status(500).json({ error: "Failed to get wallet address", details: err.message });
    }
  }
});

// Root endpoint for testing
app.get("/", (req, res) => {
  res.json({ status: "Backend server is running", endpoints: ["/sign", "/get/:id"] });
});

app.listen(3000, () => {
  console.log('🚀 Backend server started on port 3000');
  console.log('📋 Available endpoints:');
  console.log('  POST /create - Create user key and policy');
  console.log('  POST /sign - Sign transaction');
  console.log('  POST /sign-txn - Sign and execute transaction');
  console.log('  GET /get/:id - Get wallet address');
  console.log('  GET /mock - Mock transaction test');
  console.log('  GET / - Health check');
});
