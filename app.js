require('dotenv').config()

const express = require('express');
const mongoose = require('mongoose');
const crypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();



//Config JSON response
app.use(express.json());

//Models 
const User = require('./models/User')

// Open Route Public
app.get('/', (req, res)=> {
  res.status(200).json({message: "É nós, vamo nessa."})
})

//Private Route ->> NÃO ESTÁ RETORNANDO O ID, VERIFICAR 

app.get("users/:id", checkToken, async (req, res) => {  
  const id = req.params.id // vem da URL
  //check if user exists
  const user = await User.findById(id, '-passsword')

  if (!user) {
    return res.status(404).json({ msg: "User not found" })
  }
  res.status(200).json({ user })
})

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.spli(" "[1])

  if(!token){
    return res.status(401).json({msg: "Acess negative"})

  }
  try {
    const secret = process.env.SECRET 
    jwt.verify(token, secret)

    next()

  } catch(error){
    console.log("token invalido")
    res.status(400).json({msg: "Token inválido "})
  }
}

// Register User
app.post('/auth/register', async (req, res) => {
 const { name ,email, password, confirmpassword } = req.body;
  
 //validations
  if(!name) {
    return res.status(422).json({ msg: "Not found name"})
  }
  if(!email) {
    return res.status(422).json({ msg: "Not found email"})
  }
  if(!password) {
    return res.status(422).json({ msg: "Not found password"})
  }
  if( password !== confirmpassword) {
    return res.status(422).json({ msg: "Sorry passwords diferents"})
  }
  

  // check if user exists

  const userExists = await User.findOne({ email : email})

  if(userExists) {
    return res.status(422).json({ msg: "Sorry, user  email diferent"})
  }
    
  //create password 

  const salt = await crypt.genSalt(12)
  const passwordHash = await crypt.hash(password, salt)

  //create user 
  const user = new User({ 
    name,
    email,
    password: passwordHash,
  })
  try{

    await user.save()

    res.status(201).json({msg: 'User created with sucess'})

  }catch(error){
    console.log(error)

      res
      .status(500)
      .json({
        msg: "Error no servidor"})
    }
  })
//Credencials 
//Login User

app.post('/auth/login', async (req,res) => { 
  const { email, password} = req.body;
  //validating email
  if(!email) {
    return res.status(422).json({ msg: "Not found email"})
  }
  if(!password) {
    return res.status(422).json({ msg: "Not found password"})
  }
  //check user exists
  const user = await User.findOne({ email: email})

  if(!user){
    return res.status(404).json({msg: "Sorry, user not exists"})
  }
  //check user exists
  const checkPassword = await crypt.compare(password, user.password)

  if(!checkPassword) {
  return res.status(422).json({ msg: "Sorry, password is incorrect" })
}
  try{
    const secret = process.env.SECRET

    const token = jwt.sign(
      {
      id: user._id
      }, 
      secret,
    )
    return res
    .status(200)
    .json({
      msg: "auth ok", token})
  } catch(err) {
    console.log(err)
       res.status(500).json({
        msg: "Error no servidor"})
       }

       });


const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
  .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.3nkjtiv.mongodb.net/?retryWrites=true&w=majority`)
  .then(() => {
  app.listen(3000)  
  console.log("Conectou ao banco")
  })
  .catch((err) => console.log(err));
