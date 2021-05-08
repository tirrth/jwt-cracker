var http = require("http");
const crypto = require("crypto");
const variationsStream = require("variations-stream");
const pkg = require("./package.json");

const jwtCracker = () => {
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
    console.log("\n#####################################################");
    console.log("TOKEN:", token);
    if (result) {
      console.log("%c SECRET FOUND:", "color: #0F9D58");
      console.log(result);
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
  variationsStream(alphabet, maxLength)
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
        setInterval(() => {
          printResult(startTime, attempts, comb);
        }, 2500);
        // process.exit(0);
      }
    })
    .on("end", function () {
      setInterval(() => {
        printResult(startTime, attempts);
      }, 2500);
      // process.exit(1);
    });
};

function keepServerAlive() {
  setInterval(function () {
    var options = {
      host: "jwt-cracker.herokuapp.com", // Add your server's base-url
      /* port: 80, */
      path: "/",
    };
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
  }, 20 * 60 * 1000); // ping to this server every 20 minutes
}

module.exports = { jwtCracker, keepServerAlive };
