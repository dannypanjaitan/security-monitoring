const http = require("http");
const crypto = require("crypto");
const webhookHandler = require("./api/webhook");

// Setup environment secret for testing
process.env.WEBHOOK_HMAC_SECRET = "super-secret-tni-siber-key-2026";
const SECRET = process.env.WEBHOOK_HMAC_SECRET;

const PORT = 38472;

function createSignature(payload, secret) {
    return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function sendRequest(options, data) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let body = "";
            res.on("data", (chunk) => (body += chunk));
            res.on("end", () => {
                let parsed = null;
                try {
                    parsed = JSON.parse(body);
                } catch (e) {
                    parsed = body;
                }
                resolve({ statusCode: res.statusCode, data: parsed });
            });
        });
        req.on("error", reject);
        if (data) {
            req.write(data);
        }
        req.end();
    });
}

async function runTests() {
    console.log("=" .repeat(65));
    console.log("  PENGUJIAN AUTENTIKASI WEBHOOK HMAC-SHA256 - PaPK SIBER TNI");
    console.log("=" .repeat(65));

    // Create mock micro-server running webhook handler
    const server = http.createServer((req, res) => {
        // Mock res.status and res.json for Vercel Serverless environment
        res.status = function (code) {
            this.statusCode = code;
            return this;
        };
        res.json = function (obj) {
            this.setHeader("Content-Type", "application/json");
            this.end(JSON.stringify(obj));
            return this;
        };

        webhookHandler(req, res);
    });

    await new Promise((resolve) => server.listen(PORT, resolve));
    console.log(`[INIT] Test Server running on port ${PORT}\n`);

    const tests = [];
    const validPayload = JSON.stringify({
        type: "INSERT",
        table: "threat_reports",
        record: {
            threat_type: "SQL Injection",
            severity: "CRITICAL",
            source_ip: "10.12.4.99",
            description: "UNION SELECT * FROM military_personnel --"
        }
    });

    // Test 1: Valid Signature
    try {
        const signature = createSignature(validPayload, SECRET);
        const res = await sendRequest(
            {
                hostname: "localhost",
                port: PORT,
                path: "/api/webhook",
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Webhook-Signature": signature
                }
            },
            validPayload
        );

        if (res.statusCode === 200 && res.data.success === true) {
            console.log("[PASS] Test 1: Signature Valid -> HTTP 200 OK & Authenticated");
            tests.push(true);
        } else {
            console.error(`[FAIL] Test 1: Expected 200, got ${res.statusCode}`, res.data);
            tests.push(false);
        }
    } catch (err) {
        console.error("[FAIL] Test 1 Error:", err);
        tests.push(false);
    }

    // Test 2: Invalid Signature (Tampered)
    try {
        const invalidSig = "badcafe000000000000000000000000000000000000000000000000000000000";
        const res = await sendRequest(
            {
                hostname: "localhost",
                port: PORT,
                path: "/api/webhook",
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Webhook-Signature": invalidSig
                }
            },
            validPayload
        );

        if (res.statusCode === 401 && res.data.success === false) {
            console.log("[PASS] Test 2: Invalid Signature -> HTTP 401 Unauthorized");
            tests.push(true);
        } else {
            console.error(`[FAIL] Test 2: Expected 401, got ${res.statusCode}`, res.data);
            tests.push(false);
        }
    } catch (err) {
        console.error("[FAIL] Test 2 Error:", err);
        tests.push(false);
    }

    // Test 3: Missing Signature Header
    try {
        const res = await sendRequest(
            {
                hostname: "localhost",
                port: PORT,
                path: "/api/webhook",
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                }
            },
            validPayload
        );

        if (res.statusCode === 401 && res.data.success === false) {
            console.log("[PASS] Test 3: Missing Signature -> HTTP 401 Unauthorized");
            tests.push(true);
        } else {
            console.error(`[FAIL] Test 3: Expected 401, got ${res.statusCode}`, res.data);
            tests.push(false);
        }
    } catch (err) {
        console.error("[FAIL] Test 3 Error:", err);
        tests.push(false);
    }

    // Test 4: Invalid JSON Payload
    try {
        const brokenPayload = "{ unclosed_json: true ";
        const signature = createSignature(brokenPayload, SECRET);
        const res = await sendRequest(
            {
                hostname: "localhost",
                port: PORT,
                path: "/api/webhook",
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Webhook-Signature": signature
                }
            },
            brokenPayload
        );

        if (res.statusCode === 400 && res.data.success === false) {
            console.log("[PASS] Test 4: Malformed JSON -> HTTP 400 Bad Request");
            tests.push(true);
        } else {
            console.error(`[FAIL] Test 4: Expected 400, got ${res.statusCode}`, res.data);
            tests.push(false);
        }
    } catch (err) {
        console.error("[FAIL] Test 4 Error:", err);
        tests.push(false);
    }

    // Test 5: Method GET Rejected
    try {
        const res = await sendRequest({
            hostname: "localhost",
            port: PORT,
            path: "/api/webhook",
            method: "GET"
        });

        if (res.statusCode === 405) {
            console.log("[PASS] Test 5: Method GET -> HTTP 405 Method Not Allowed");
            tests.push(true);
        } else {
            console.error(`[FAIL] Test 5: Expected 405, got ${res.statusCode}`);
            tests.push(false);
        }
    } catch (err) {
        console.error("[FAIL] Test 5 Error:", err);
        tests.push(false);
    }

    server.close();

    const passedCount = tests.filter(Boolean).length;
    console.log("\n" + "=" .repeat(65));
    console.log(`  HASIL PENGUJIAN: ${passedCount}/${tests.length} TEST BERHASIL (PASS)`);
    console.log("=" .repeat(65));

    if (passedCount === tests.length) {
        console.log("  STATUS: PENGUJIAN HMAC-SHA256 WEBHOOK DINYATAKAN LULUS (100% PASS)\n");
        process.exit(0);
    } else {
        console.log("  STATUS: ADA PENGUJIAN YANG GAGAL.\n");
        process.exit(1);
    }
}

runTests();
