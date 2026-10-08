const crypto = require("crypto");

function getRawBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];

        req.on("data", (chunk) => {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });

        req.on("end", () => {
            resolve(Buffer.concat(chunks));
        });

        req.on("error", reject);
    });
}

function verifySignature(rawBody, signature, secret) {
    if (!signature || !secret) {
        return false;
    }

    const expectedSignature = crypto
        .createHmac("sha256", secret)
        .update(rawBody)
        .digest("hex");

    const received = Buffer.from(signature, "utf8");
    const expected = Buffer.from(expectedSignature, "utf8");

    if (received.length !== expected.length) {
        return false;
    }

    return crypto.timingSafeEqual(received, expected);
}

module.exports = async (req, res) => {
    // Hanya menerima POST
    if (req.method !== "POST") {
        return res.status(405).json({
            success: false,
            error: "Method Not Allowed"
        });
    }

    // Secret wajib berasal dari environment variable
    const secret = process.env.WEBHOOK_HMAC_SECRET;

    if (!secret) {
        console.error("WEBHOOK_HMAC_SECRET is not configured");

        return res.status(500).json({
            success: false,
            error: "Webhook secret is not configured"
        });
    }

    try {
        // Ambil raw request body untuk validasi HMAC
        const rawBody = await getRawBody(req);

        // Signature dikirim melalui HTTP header
        const signature =
            req.headers["x-webhook-signature"] ||
            req.headers["x-signature"];

        // Validasi HMAC-SHA256
        const valid = verifySignature(
            rawBody,
            signature,
            secret
        );

        if (!valid) {
            console.warn("Invalid webhook signature");

            return res.status(401).json({
                success: false,
                error: "Invalid webhook signature"
            });
        }

        // Parse JSON setelah signature berhasil diverifikasi
        let payload;

        try {
            payload = JSON.parse(rawBody.toString("utf8"));
        } catch (error) {
            return res.status(400).json({
                success: false,
                error: "Invalid JSON payload"
            });
        }

        console.log("Valid security webhook received:", {
            timestamp: new Date().toISOString(),
            event: payload.event || null
        });

        return res.status(200).json({
            success: true,
            message: "Webhook authenticated successfully",
            received: true
        });

    } catch (error) {
        console.error("Webhook processing error:", error);

        return res.status(500).json({
            success: false,
            error: "Internal server error"
        });
    }
};

// Nonaktifkan body parser bawaan agar raw body dapat dibaca
module.exports.config = {
    api: {
        bodyParser: false
    }
};