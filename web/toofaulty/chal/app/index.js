const express = require("express");
const nunjucks = require("nunjucks");
const bodyParser = require("body-parser");
const session = require("express-session");
const routes = require("./routes/routes");

require("dotenv").config();

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use("/public", express.static("public"));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

nunjucks.configure("views", {
  autoescape: true,
  express: app,
});

app.use(routes());

(async () => {
  app.listen(8002, "0.0.0.0", () => console.log("Listening on port 8002"));
})();
