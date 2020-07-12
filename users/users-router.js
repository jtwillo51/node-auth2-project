const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const users = require("./users-model");
const restrict = require("../middleware/restrict");

const router = express.Router();

router.post("/register", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await users.findBy({ username }).first();
    if (user) {
      return res.status(409).json({
        message: "Username is already taken",
      });
    }
    const newUser = await users.add({
      username,
      password: await bcrypt.hash(password, 13),
    });

    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});
router.post("/login", async (req, res, next) => {
  try {
      const {username, password} = req.body
      const user = await users.findBy({username}).first()

      if(!user){
          return res.status(401).json({
              message: "Invalid credentials"
          })
      }

      const passwordValid = await bcrypt.compare(password, user.password)

      if(!passwordValid){
          return res.status(401).json({
              message: "Invalid credentials"
          })
      }

      const payload = {
          userId: user.id,
          username: user.username
      }

      res.cookie("token", jwt.sign(payload, process.env.JWT_SECRET))

      res.json(payload)
  } catch (err) {
    next(err);
  }
});
router.get("/users", restrict(), async (req, res, next) => {
  try {
      res.json(await users.find())
  } catch (err) {
    next(err);
  }
});

module.exports = router;
