const crypto = require('crypto');
const express = require('express');
const app = express();

const cors = require('cors');
app.use(cors());

// Replace this with the actual secret key stored securely in the client's database
// Example secret key: '4b7b29f3-b90c-49c0-8bcb-682846d88b72' 
// Use the secret_key stored securely in the client's system.
// Alternatively, if the client opts to use API key, they can use the API key from the Trackier panel or using the api endpoints to get latest API key.
const secret_key = '4b7b29f3-b90c-49c0-8bcb-682846d88b72';

app.use(express.json());

// Health check route for server status
app.get("/health", (req, res) => {
    res.status(200).json({ message: "Health Check" })
})

// Webhook endpoint to handle the incoming event
app.post('/webhook', (req, res) => {
    // Extract headers and body from the request
    const { headers, body } = req;

    // Destructure the required fields from the body
    const { timestamp } = body;

    // Log the request body and headers for debugging purposes
    console.log("body is", body);
    console.log("headers are", headers);

    // Extract the received hashed key from the request headers
    const receivedHashedKey = headers['x-hashed-key'];

    // Step 1: Rehash the timestamp using the client's secret_key
    const recalculatedHashedKey = crypto
        .createHmac('sha256', secret_key)  // Create HMAC using SHA-256 and the secret_key
        .update(timestamp)                 // Update HMAC with the timestamp from the body
        .digest('hex');                    // Output as hex digest (hashed key)

    // Step 2: Compare the recalculated hashed key with the one received in the headers
    if (receivedHashedKey === recalculatedHashedKey) {
        // Validation successful, process the event
        console.log('Valid event received:', body);

        // Respond back with a success status
        res.status(200).json({ success: true, message: 'Event processed successfully' });
    } else {
        // Validation failed, log the error and respond with a failure status
        console.error('Invalid hashed key, potential tampering detected');
        res.status(400).json({ success: false, message: 'Invalid signature' });
    }
});

// Start the server
const port = process.env.PORT || 8000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
