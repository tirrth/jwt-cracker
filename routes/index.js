var express = require("express");
var router = express.Router();

/* GET home page. */
router.get("/", function (req, res, next) {
  res.render("index", {
    title: "JWT Cracker",
    jwtCracker: global.jwtCracker,
    currentTime: new Date().toUTCString(),
  });
});

module.exports = router;
