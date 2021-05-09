var http = require("http");
const crypto = require("crypto");
const variationsStream = require("variations-stream");
const pkg = require("./package.json");

const jwtCracker = () => {
  const defaultAlphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const defaultMaxLength = 12;
  const defaultMinLength = 1;
  // const defaultToken =
  // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o";
  // const token = process.env.TOKEN || defaultToken;
  const token = process.env.TOKEN;
  const alphabet = process.env.ALPHABET || defaultAlphabet;
  const maxLength = Number(process.env.MAX_LENGTH) || defaultMaxLength;
  const minLength = Number(process.env.MIN_LENGTH) || defaultMinLength;

  if (typeof token === "undefined" || token === "--help") {
    console.log(
      `jwt-cracker version ${pkg.version}
  Usage:
    jwt-cracker <token> [<alphabet>] [<maxLength>]
    token       the full HS256 jwt token to crack
    alphabet    the alphabet to use for the brute force (default: ${defaultAlphabet})
    maxLength   the max length of the string generated during the brute force (default: ${defaultMaxLength})
    minLength   the min length of the string generated during the brute force (default: ${defaultMinLength})`
    );
    // process.exit(0);
    return;
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
    console.log("\n#####################################################");
    console.log("TOKEN:", token);
    if (result) {
      console.log(`%c SECRET FOUND: ${result}`, "color: #0F9D58");
    } else {
      console.log("%c SECRET NOT FOUND", "color: #DB4437");
    }
    console.log("Time taken (sec):", (new Date().getTime() - startTime) / 1000);
    console.log("Total Attempts:", attempts);
    console.log("#####################################################");
  };

  const [header, payload, signature] = token.split(".");
  const content = `${header}.${payload}`;

  const startTime = new Date().getTime();
  let attempts = 0;
  let is_secret_found = false;
  variationsStream(alphabet, { maxLength, minLength })
    .on("data", function (comb) {
      attempts++;
      const currentSignature = generateSignature(content, comb);
      if (attempts % 100000 === 0) {
        console.log(
          `\n------------------- Attempts: ${attempts} -------------------`
        );
        console.log("Guess: ", comb);
        console.log(
          "-------------------------------------------------------------"
        );
      }
      if (currentSignature == signature) {
        is_secret_found = true;
        setInterval(() => {
          printResult(startTime, attempts, comb);
        }, 2500);
        // process.exit(0);
      }
    })
    .on("end", function () {
      !is_secret_found &&
        setInterval(() => {
          printResult(startTime, attempts);
        }, 2500);
      // process.exit(1);
    });
};

function keepServerAlive(options) {
  setInterval(function () {
    http
      .get(options, function (res) {
        res.on("data", function (chunk) {
          try {
            // optional logging... disable after it's working console.log("HEROKU RESPONSE: " + chunk);
            console.log("%c SERVER IS ALIVE", "color: #0F9D58");
          } catch (err) {
            console.log(err.message);
            console.log("%c FAILED TO KEEP SERVER ALIVE", "color: #DB4437");
          }
        });
      })
      .on("error", function (err) {
        console.log("Error: " + err.message);
      });
  }, 20 * 60 * 1000); // ping to given server every 20 minutes
}

module.exports = { jwtCracker, keepServerAlive };
