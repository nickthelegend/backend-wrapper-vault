import { Buffer } from 'buffer';

// Your transaction data
const transactionData = {
  "sig": "8n7XV64vAEpbkcskdriQ5KgzI3uCWcNAu3D0wHAje4xJxQmRZyilUazbf9vRjXd3/07y6m+NUs/Dp9jSM5d4AQ==",
  "txn": {
    "arcv": "ZPdly4ZSV5z4WC5fGho6fKV7i6ALv6EHnQKaI0qCkKo=",
    "type": "axfer",
    "xaid": 733709260,
    "fee": 1000,
    "fv": 51138260,
    "gen": "testnet-v1.0",
    "gh": "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
    "lv": 51139260,
    "snd": "ZPdly4ZSV5z4WC5fGho6fKV7i6ALv6EHnQKaI0qCkKo="
  }
};

// Convert to base64
const base64Txn = Buffer.from(JSON.stringify(transactionData)).toString('base64');
console.log('Base64 encoded transaction:');
console.log(base64Txn);

// Create curl command
const curlCommand = `curl -X POST http://127.0.0.1:3000/sign -H "Content-Type: application/json" -d "{\\"txn\\":\\"${base64Txn}\\",\\"oauthToken\\":\\"mockToken\\"}"`;
console.log('\nCurl command:');
console.log(curlCommand);