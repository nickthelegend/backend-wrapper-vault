import * as algosdk from "algosdk";
import axios from "axios";

const VAULT_ADDR = "http://127.0.0.1:8200";
const VAULT_TOKEN = "root";

async function getVaultAddress() {
  const res = await axios.get(`${VAULT_ADDR}/v1/transit/keys/algo-user-123`, {
    headers: { "X-Vault-Token": VAULT_TOKEN },
  });

  const pubB64 = res.data.data.keys["1"].public_key; // Vault stores it under key version
  const pubBytes = new Uint8Array(Buffer.from(pubB64, "base64"));
  const addr = algosdk.encodeAddress(pubBytes);
  console.log("Vault public address:", addr);
}

getVaultAddress();
