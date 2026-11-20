
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "https://images.unsplash.com", "data:"],
      connectSrc: ["'self'", "https://api.msg91.com"],
    }
  }
}));

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const AUTH_KEY = process.env.MSG91_AUTH_KEY;
const WIDGET_ID = process.env.MSG91_WIDGET_ID;
const TEMPLATE_ID = process.env.MSG91_TEMPLATE_ID;

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function validMobile(mobile) {
  return typeof mobile === "string" && /^[6-9]\d{9}$/.test(mobile);
}

app.post("/api/send-otp", otpLimiter, async (req, res) => {
  const { mobile } = req.body || {};

  if (!validMobile(mobile)) {
    return res.status(400).json({ error: "Invalid mobile number." });
  }

  if (!AUTH_KEY || !WIDGET_ID) {
    return res.status(503).json({ error: "SMS service is not configured." });
  }

  try {
    const response = await fetch("https://control.msg91.com/api/v5/widget/sendOtp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "authkey": AUTH_KEY
      },
      body: JSON.stringify({
        widgetId: WIDGET_ID,
        identifier: "91" + mobile
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(502).json({ error: "SMS provider rejected the request." });
    }

    res.json({ success: true, message: "OTP request submitted." });
  } catch (error) {
    res.status(502).json({ error: "SMS service unavailable." });
  }
});

app.post("/api/verify-otp", verifyLimiter, async (req, res) => {
  const { mobile, otp } = req.body || {};

  if (!validMobile(mobile) || !/^\d{6}$/.test(otp || "")) {
    return res.status(400).json({ error: "Invalid mobile number or OTP." });
  }

  if (!AUTH_KEY) {
    return res.status(503).json({ error: "SMS service is not configured." });
  }

  try {
    const response = await fetch("https://control.msg91.com/api/v5/widget/verifyOtp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "authkey": AUTH_KEY
      },
      body: JSON.stringify({
        widgetId: WIDGET_ID,
        identifier: "91" + mobile,
        otp
      })
    });

    const data = await response.json();

    if (!response.ok || data.type === "error") {
      return res.status(400).json({ error: "OTP verification failed." });
    }

    res.json({ success: true, message: "Mobile verified." });
  } catch (error) {
    res.status(502).json({ error: "Verification service unavailable." });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Demo server running on port " + PORT));
