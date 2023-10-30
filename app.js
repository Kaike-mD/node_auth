import "dotenv/config.js";
import express from "express";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import User from "./models/User.js";

const app = express();

// CONFIG JSON RESPONSE
app.use(express.json());


// OPEN ROUTE / PUBLIC ROUTE
app.get('/', (req, res) => {
    res.status(200).json({msg: "Bem vindo a nossa API"})
});

// PRIVATE ROUTE
app.get("/user/:id", checkToken, async (req, res) => {

    const id = req.params.id;
    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado!" })
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
     return res.status(401).json({msg:'Acesso negado!'})
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);

        next();
    } catch (error) {
        res.status(400).json({ msg: "Token inválido!"})
    }
    
}

// CREDENCIAIS
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

// REGISTER USER
app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmpassword} = req.body;

    // VALIDATIONS
    if (!name) {
        return res.status(422).json({msg: "O nome é obrigatório!"})
    }

    if (!email) {
        return res.status(422).json({msg: "O email é obrigatório!"})
    }

    if (!password) {
        return res.status(422).json({msg: "A senha é obrigatória!"})
    }
    
    if (password !== confirmpassword) {
        return res.status(422).json({msg: "As senhas são diferentes!"})
    }

    // CHECK IF USER EXISTS
    const userExists = await User.findOne({ email: email})

    if (userExists) {
        return res.status(422).json({msg: "Por favor, utilize outro e-mail!"})
    }

    // CREATE PASSWPORD
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // CREATE USER
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save();
        return res.status(201).json({msg: "Usuário criado com sucesso!"})
        
    } catch (error) {
        console.log(error);
        res.status(500).json({msg: "Aconteceu um erro no servidor!"})
    }
});

// LOGIN USER
app.post("/auth/login", async(req, res) => {
    const {email, password} = req.body;


    // VALIDATIONS
    if (!email) {
        return res.status(422).json({msg: "O email é obrigatório!"})
    }

    if (!password) {
        return res.status(422).json({msg: "A senha é obrigatória!"})
    }

    const user = await User.findOne({ email: email})

    if (!user) {
        return res.status(404).json({msg: "Usuário não encontrado!"})

    }

    // CHECK IF PASSWORD MATCH
    const checkPassword = await bcrypt.compare(password, user.password)
    
    if(!checkPassword) {
        return res.status(422).json({ msg: "Senha incorreta!" })
    }

    try {

        const secret = process.env.SECRET;
        const token = jwt.sign(
            {
            id: user._id,
        },
        secret,
    )

    res.status(200).json({ msg: "Autenticação realizada com sucesso", token })
        
    } catch (err) {
        console.log(err);
        res.status(500).json({msg: "Aconteceu um erro no servidor!"})
    }
})




// CONNECT
mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.qsvbhpc.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        console.log("Conectou ao banco")
    })
    .catch((err) => console.log(err))

app.listen(3000);