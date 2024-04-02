const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const nunjucks = require("nunjucks");
const cookieParser = require("cookie-parser");
const routes = require("./routes/routes");

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.set("trust proxy", process.env.PROXY !== "false");
app.use("/public", express.static("public"));

nunjucks.configure("views", {
  autoescape: true,
  express: app,
  views: "templates",
});

app.use(routes());

app.all("*", (req, res) => {
  return res.status(404).send({
    message: "404 page not found",
  });
});

(async () => {
  app.listen(80, "0.0.0.0", () => console.log("Listening on port 80"));
})();
