const express = require("express");
const router = express.Router({ caseSensitive: true });
const dataBaseHandler = require("../config/DataBaseHandler");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const UAParser = require("ua-parser-js");
const svgCaptcha = require("svg-captcha");
const { generateDeviceId, isTrusted } = require("../utils/utils.js");
const {
  checkAuthenticated,
  check2FARequired,
} = require("../utils/sessionMiddleware");

require("dotenv").config();

router.get("/", [checkAuthenticated, check2FARequired], async (req, res) => {
  const message =
    req.session.user.username === "admin" ? process.env.FLAG : "user";
  res.render("index.html", { message });
});

//Generate svg captcha
router.get("/captcha", [checkAuthenticated], async (req, res) => {
  const captcha = svgCaptcha.create();

  req.session.captcha = captcha.text;

  res.type("svg");
  res.status(200).send(captcha.data);
});

// Registration Page Route
router.get("/register", (req, res) => {
  res.render("register.html");
});

// Register Route
router.post("/register", async (req, res) => {
  let { username, password } = req.body;

  try {
    const [checkResults] = await dataBaseHandler.queryAsync(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (checkResults.length > 0) {
      return res.redirect("/register?error=Username exists");
    }

    await dataBaseHandler.queryAsync(
      "INSERT INTO users (username, password, two_factor, secret, trusted_device) VALUES (?, ?, false, '', '')",
      [username, password]
    );
    res.redirect("/login");
  } catch (err) {
    console.error("Error in /register:", err);
    res.redirect("/register?error=Check failed");
  }
});

router.get("/login", (req, res) => {
  return res.render("login.html");
});

// Login Post Route
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [results] = await dataBaseHandler.queryAsync(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (results.length === 0) {
      return res.redirect("/login?error=Invalid credentials");
    }

    const user = results[0];
    if (user.password === password) {
      req.session.authenticated = true;
      req.session.user = user;

      if (user.two_factor && !isTrusted(user, req.headers["x-device-id"])) {
        return res.redirect("/2fa");
      }
      req.session.verified = true; // Assuming direct verification if 2FA is not enabled or device is trusted
      return res.redirect("/");
    } else {
      return res.redirect("/login?error=Invalid credentials");
    }
  } catch (err) {
    console.error("Error in /login:", err);
    res.redirect("/login?error=checkFailed");
  }
});

// 2FA Setup Route
router.get("/setup-2fa", [checkAuthenticated], async (req, res) => {
  try {
    const username = req.session.user.username;
    const [results] = await dataBaseHandler.queryAsync(
      "SELECT secret FROM users WHERE username = ?",
      [username]
    );

    if (results.length > 0 && results[0].secret) {
      return res.redirect("/?error=Already enabled 2FA");
    } else {
      const secret = speakeasy.generateSecret({ length: 20 });
      QRCode.toDataURL(secret.otpauth_url, async (qrErr, data_url) => {
        if (qrErr) {
          console.error("Error generating QR Code:", qrErr);
          return res
            .status(500)
            .send("Error generating QR code. Please try again later.");
        }
        await dataBaseHandler.queryAsync(
          "UPDATE users SET secret = ?, two_factor = 1 WHERE username = ?",
          [secret.base32, username]
        );
        res.render("setup-2fa.html", { data_url, user: username });
      });
    }
  } catch (err) {
    console.error("Error in /setup-2fa:", err);
    res.status(500).send("Error setting up 2FA. Please try again later.");
  }
});

router.get("/2fa", [checkAuthenticated], async (req, res) => {
  if (req.session.verified || req.session.user.two_factor === 0) {
    return res.redirect("/");
  }

  const username = req.session.user.username;
  const deviceId = req.headers["x-device-id"];

  try {
    const [results] = await dataBaseHandler.queryAsync(
      "SELECT trusted_device FROM users WHERE username = ?",
      [username]
    );

    if (results.length > 0) {
      const user = results[0];

      if (isTrusted(user, deviceId)) {
        res.redirect("/");
      } else {
        res.render("verify-2fa.html");
      }
    } else {
      console.error("No user found in session.");
      res.redirect("/login?error=Authentication error");
    }
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).send("An error occurred. Please try again later.");
  }
});

router.post("/verify-2fa", [checkAuthenticated], async (req, res) => {
  const { token, trustDevice, captcha } = req.body;
  const username = req.session.user.username;

  try {
    const [results] = await dataBaseHandler.queryAsync(
      "SELECT secret, trusted_device FROM users WHERE username = ?",
      [username]
    );
    if (results.length === 0 || !results[0].secret) {
      return res.redirect("/setup-2fa");
    }
    if (req.session.captcha !== captcha) {
      return res.redirect("/2fa?error=Invalid captcha");
    }

    const userSecret = results[0].secret;
    const verified = speakeasy.totp.verify({
      secret: userSecret,
      encoding: "base32",
      token,
    });

    if (verified) {
      req.session.verified = true;

      if (trustDevice === true) {
        const ua = req.headers["user-agent"];
        const parser = new UAParser(ua);
        const browserDetails = parser.getResult();
        const browserVersion = browserDetails.browser.version.match(
          /^(\d+\.\d+)/
        )
          ? browserDetails.browser.version.match(/^(\d+\.\d+)/)[0]
          : "unknown";

        const newDeviceId = generateDeviceId(
          `${browserDetails.browser.name} ${browserVersion}`
        );

        await dataBaseHandler.queryAsync(
          "UPDATE users SET trusted_device = ? WHERE username = ?",
          [newDeviceId, username]
        );
      }

      res.redirect("/");
    } else {
      res.redirect("/2fa?error=Verification failed");
    }
  } catch (err) {
    console.error("Error in /verify-2fa:", err);
    res.status(500).send("An error occurred. Please try again later.");
  }
});

// Logout Route
router.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("Could not log out. Please try again.");
    }
    res.clearCookie("connect.sid");
    res.redirect("/login");
  });
});

module.exports = () => {
  return router;
};
