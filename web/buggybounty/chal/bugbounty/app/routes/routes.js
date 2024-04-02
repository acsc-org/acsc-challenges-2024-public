const { isAdmin, authSecret } = require("../utils/auth.js");
const express = require("express");
const router = express.Router({ caseSensitive: true });
const visit = require("../utils/bot.js");
const request = require("request");
const ssrfFilter = require("ssrf-req-filter");

router.get("/", (req, res) => {
  return res.render("index.html");
});

router.get("/triage", (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).send({
        err: "Permission denied",
      });
    }
    let bug_id = req.query.id;
    let bug_url = req.query.url;
    let bug_report = req.query.report;

    return res.render("triage.html", {
      id: bug_id,
      url: bug_url,
      report: bug_report,
    });
  } catch (e) {
    res.status(500).send({
      error: "Server Error",
    });
  }
});

router.post("/report_bug", async (req, res) => {
  try {
    const id = req.body.id;
    const url = req.body.url;
    const report = req.body.report;
    await visit(
      `http://127.0.0.1/triage?id=${id}&url=${url}&report=${report}`,
      authSecret
    );
  } catch (e) {
    console.log(e);
    return res.render("index.html", { err: "Server Error" });
  }
  const reward = Math.floor(Math.random() * (100 - 10 + 1)) + 10;
  return res.render("index.html", {
    message: "Rewarded " + reward + "$",
  });
});

router.get("/check_valid_url", async (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).send({
        err: "Permission denied",
      });
    }

    const report_url = req.query.url;
    const customAgent = ssrfFilter(report_url);

    request(
      { url: report_url, agent: customAgent },
      function (error, response, body) {
        if (!error && response.statusCode == 200) {
          res.send(body);
        } else {
          console.error("Error:", error);
          res.status(500).send({ err: "Server error" });
        }
      }
    );
  } catch (e) {
    res.status(500).send({
      error: "Server Error",
    });
  }
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

module.exports = () => {
  return router;
};
