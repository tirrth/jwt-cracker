var http = require("http");
const crypto = require("crypto");
const VariationsStream = require("variations-stream");
const pkg = require("./package.json");

const jwtCracker = (callback) => {
  const defaultAlphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const defaultMaxLength = 12;
  const defaultMinLength = 1;
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
    return false;
  }

  const startTime = new Date();
  global.jwtCracker = { attempts: 0 };
  global.jwtCracker.startTime = startTime.toUTCString();
  global.jwtCracker.token = token;

  const generateSignature = function (content, secret) {
    return crypto
      .createHmac("sha256", secret)
      .update(content)
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  };

  const printResult = function (startTime, attempts, result, endTime) {
    console.log("\n#####################################################");
    if (result) {
      console.log(`%c SECRET FOUND: ${result}`, "color: #0F9D58");
    } else {
      console.log("%c SECRET NOT FOUND", "color: #DB4437");
    }
    console.log(
      " Time taken (sec):",
      (endTime.getTime() - startTime.getTime()) / 1000
    );
    console.log(" Total Attempts:", attempts);
    console.log("#####################################################\n");
  };

  const [header, payload, signature] = token.split(".");
  const content = `${header}.${payload}`;

  let attempts = 0;
  let private_key = null;
  const variationsStream = new VariationsStream(alphabet, {
    maxLength,
    minLength,
  });
  variationsStream
    .on("data", function (comb) {
      attempts++;
      global.jwtCracker.attempts = attempts;
      global.jwtCracker.currentGuess = comb;
      const currentSignature = generateSignature(content, comb);
      if (attempts % 100000 === 0) {
        console.log(
          `\n------------------- Attempts: ${attempts} -------------------`
        );
        console.log(" Guess: ", comb);
        console.log(
          "-------------------------------------------------------------\n"
        );
      }
      if (currentSignature == signature) {
        private_key = comb;
        variationsStream._exit();
      }
    })
    .on("end", function () {
      const endTime = new Date();
      printResult(startTime, attempts, private_key, endTime);
      global.jwtCracker.currentGuess = null;
      callback({
        attempts,
        private_key,
        endTime: endTime.toUTCString(),
        is_secret_found: !!private_key,
      });
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
