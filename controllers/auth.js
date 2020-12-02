const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).render("login", {
        message: "Email and password must be filled",
      });
    }
    db.query(
      "SELECT * FROM users WHERE user_email = ?",
      [email],
      async (err, results) => {
        if (
          !results ||
          !(await bcrypt.compare(password, results[0].user_password))
        ) {
          res.status(401).render("login", {
            message: "Emair or password incorect",
          });
        } else {
          const id = results[0].id;
          const token = jwt.sign({ id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN,
          });
          const cookieOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
            ),
            httpOnly: true,
          };
          res.cookie("jwt", token, cookieOptions);
          res.status(200).redirect("/");
        }
      }
    );
  } catch (err) {
    console.log(err);
  }
};

exports.logout = (req, res) => {
  res.cookie("jwt", " ", { maxAge: 1 });
  res.status(200).redirect("/");
};

exports.register = (req, res) => {
  console.log(req.body);

  const {
    name,
    lastName,
    email,
    password,
    passwordConfirm,
    highSchool,
  } = req.body;

  db.query(
    "SELECT user_email FROM users WHERE user_email = ?",
    [email],
    async (error, results) => {
      if (error) {
        console.log(error);
      }
      if (results.length > 0) {
        return res.render("register", {
          message: "That email is already in use",
        });
      } else if (password !== passwordConfirm) {
        return res.render("register", {
          message: "Passwords do not match",
        });
      }
      let hashedPassword = await bcrypt.hash(password, 8);
      console.log(hashedPassword);

      db.query(
        "INSERT INTO users SET ?",
        {
          user_name: name,
          user_last_name: lastName,
          user_email: email,
          user_password: hashedPassword,
          user_high_school: highSchool,
        },
        (error, results) => {
          if (error) {
            console.log(error);
          } else {
            console.log(results);
            return res.render("register", {
              message: "User registered",
            });
          }
        }
      );
    }
  );
};
