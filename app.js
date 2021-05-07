var createError = require("http-errors");
var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");

// -------------------------------------------------------------------------------------------------------- //
const crypto = require("crypto");
const variationsStream = require("variations-stream");
const pkg = require("./package.json");

const defaultAlphabet =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const defaultMaxLength = 12;
const defaultToken =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const token = process.env.TOKEN || defaultToken;
const alphabet = process.env.ALPHABET || defaultAlphabet;
const maxLength = Number(process.env.LENGTH) || defaultMaxLength;

if (typeof token === "undefined" || token === "--help") {
  console.log(
    `jwt-cracker version ${pkg.version}
  Usage:
    jwt-cracker <token> [<alphabet>] [<maxLength>]
    token       the full HS256 jwt token to crack
    alphabet    the alphabet to use for the brute force (default: ${defaultAlphabet})
    maxLength   the max length of the string generated during the brute force (default: ${defaultMaxLength})
`
  );
  process.exit(0);
}

const generateSignature = function (content, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(content)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
};

const printResult = function (startTime, attempts, result) {
  if (result) {
    console.log("SECRET FOUND:", result);
  } else {
    console.log("SECRET NOT FOUND");
  }
  console.log("Time taken (sec):", (new Date().getTime() - startTime) / 1000);
  console.log("Attempts:", attempts);
};

const [header, payload, signature] = token.split(".");
const content = `${header}.${payload}`;

const startTime = new Date().getTime();
let attempts = 0;

variationsStream(alphabet, maxLength)
  .on("data", function (comb) {
    attempts++;
    const currentSignature = generateSignature(content, comb);
    if (attempts % 100000 === 0) {
      console.log("Attempts:", attempts);
    }
    if (currentSignature == signature) {
      printResult(startTime, attempts, comb);
      process.exit(0);
    }
  })
  .on("end", function () {
    printResult(startTime, attempts);
    process.exit(1);
  });
// -------------------------------------------------------------------------------------------------------- //

var indexRouter = require("./routes/index");

var app = express();

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use("/", indexRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

module.exports = app;
