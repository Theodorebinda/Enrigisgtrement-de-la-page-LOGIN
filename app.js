const express = require("express");
const ejs = require("ejs");
const path = require("path");
const session = require("express-session");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");

const app = express();
const prisma = new PrismaClient();

app.engine("html", ejs.__express);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  name: "sid",
  secret: "secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 3600000, // 1 heure
    secure: false
  },
}));
app.use(express.static(path.join(__dirname, "public")));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Middleware pour vérifier si l'utilisateur est connecté
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  next();
};

app.get("/", async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    console.log(req.session);
    res.render("Login", { users });
  } catch (error) {
    console.error(error);
    res.status(500).send("Une erreur est survenue.");
  }
});

app.post("/", async (req, res) => {
  const { email, password } = req.body;
  if (email && password) {
    try {
      const user = await prisma.user.findFirst({ where: { email } });
      if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user.id;
        return res.json({ success: true, redirectUrl: "/cong2" });
      }
      res.status(401).json({ success: false, message: "Email ou mot de passe incorrect." });
    } catch (error) {
      res.status(500).json({ success: false, message: "Une erreur est survenue." });
      console.error(error);
    }
  }
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { lastName, firstName, email, password } = req.body;
  if (lastName && firstName && email && password) {
    try {
      const existingUser = await prisma.user.findFirst({ where: { email } });
      if (!existingUser) {
        const salt = await bcrypt.genSalt(10);
        const pwTosave = await bcrypt.hash(password, salt);
        
        const newUser = await prisma.user.create({
          data: {
            lastName,
            firstName,
            email,
            password: pwTosave
          }
        });
        
        req.session.userId = newUser.id;
        return res.redirect("/cong2");
      }
      res.status(400).send("L'utilisateur existe déjà.");
    } catch (error) {
      res.status(500).send("Une erreur est survenue lors de la création de l'utilisateur.");
      console.error(error);
    }
  }
});

app.get("/re", (req, res) => {
  res.render("re");
});

app.post("/re", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await authenticateUser(email, password);
    req.session.userId = user.id;
    res.redirect("/cong2");
  } catch (error) {
    res.status(401).send("Identifiants invalides.");
  }
});

app.get("/cong2", requireAuth, (req, res) => {
  res.render("cong2");
});

app.get("/for", (req, res) => {
  res.render("for");
});

// Route pour la déconnexion
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Une erreur est survenue lors de la déconnexion.");
    }
    res.redirect("/");
  });
});

app.listen(4001, () => {
  console.log("L'application tourne au port 4001");
});
