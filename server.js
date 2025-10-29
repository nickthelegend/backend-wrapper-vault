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
app.post("/sign", async (req, res) => {
  const { txn, oauthToken } = req.body;
  
  console.log("Received request:", { txn: txn?.substring(0, 50) + "...", oauthToken });

  const user = verifyOAuthToken(oauthToken);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  try {
    // Parse the transaction from base64
    const txnObject = JSON.parse(Buffer.from(txn, 'base64').toString());
    
    // Encode transaction for signing using Algorand SDK
    const txnToSign = algosdk.encodeObj(txnObject.txn);
    
    const response = await axios.post(
      `${VAULT_ADDR}/v1/transit/sign/algo-user-${user.uid}`,
      { input: Buffer.from(txnToSign).toString("base64") },
      { headers: { "X-Vault-Token": VAULT_TOKEN } }
    );

    const signature = response.data.data.signature.replace('vault:v1:', '');
    
    // Attach signature to txn object
    const signedTxn = {
      txn: txnObject.txn,
      sig: signature
    };
    
    // Encode as signed bytes using Algorand SDK
    const signedBytes = algosdk.encodeObj(signedTxn);
    
    // Execute the signed bytes
    const txnResult = await algodClient.sendRawTransaction(signedBytes).do();
    
    res.json({ 
      signedBytes: Buffer.from(signedBytes).toString('base64'),
      txId: txnResult.txId
    });
  } catch (err) {
    console.error("Vault error:", err.response?.data || err.message);
    res.status(500).json({ error: "Signing failed", details: err.message });
  }
});

// Root endpoint for testing
app.get("/", (req, res) => {
  res.json({ status: "Backend server is running", endpoints: ["/sign"] });
});

app.listen(3000, () => console.log("Backend running on port 3000"));
