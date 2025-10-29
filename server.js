import express from "express";
import axios from "axios";

const app = express();

// Use express.json() middleware with proper configuration
app.use(express.json({ limit: '10mb' }));

const VAULT_ADDR = "http://127.0.0.1:8200";
const VAULT_TOKEN = "root";

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
  if (!user) return res.status(401).send("Unauthorized");

  try {
    const response = await axios.post(
      `${VAULT_ADDR}/v1/transit/sign/algo-user-${user.uid}`,
      { input: Buffer.from(txn).toString("base64") },
      { headers: { "X-Vault-Token": VAULT_TOKEN } }
    );

    res.json({ signature: response.data.data.signature });
  } catch (err) {
    console.error("Vault error:", err.response?.data || err.message);
    res.status(500).send("Signing failed");
  }
});

// Root endpoint for testing
app.get("/", (req, res) => {
  res.json({ status: "Backend server is running", endpoints: ["/sign"] });
});

app.listen(3000, () => console.log("Backend running on port 3000"));
