import axios from 'axios';

async function testEndpoint() {
  try {
    const response = await axios.post('http://127.0.0.1:3000/sign', {
      txn: 'aGVsbG8gd29ybGQ=',
      oauthToken: 'mockToken'
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Success:', response.data);
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

testEndpoint();