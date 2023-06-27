require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors')

const app = express()

app.use(cors())

// JSON response
app.use(express.json())

//models
const User = require('./models/User')


//ROTA PUBLICA
app.get('/', (req,res) =>{
    res.status(200).json({msg:"Nova API "})
})

// Rota privada
app.get('/user/:id', checkToken, async (req,res) =>{
    const id = req.params.id

    //checando se o usuario existe
    const user = await User.findById(id, '-password')
 
    if(!user){
        res.status(404).json({msg:" Usuario não encontrado "})
    }

    res.status(200).json({user})
})



function checkToken( req, res, next){

const authHeader = req.headers['authorization']
const token = authHeader && authHeader.split(' ')[1]

if(!token){
    return res.status(401).json({msg: "Acesso negado"})
}
try{
    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()

   } catch(error){
       console.log(error)
       res.status(400).json({msg: 'TOKEN INVALIDO!!!'})
   
   }

}



// criar usuario
app.post('/auth/register', async(req,res)=>{

    const {name, password} = req.body
    
    //validação

    if(!name){
        return res.status(422).json({msg:"Login incorreto"})
    }
    if(!password){
        return res.status(422).json({msg:"Login incorreto"})
    }


    //checando se o usuario já existe
    const userExist = await User.findOne({name: name})

    if(userExist){
        return res.status(422).json({msg:"utilize outro nome"})
    }
   
// senha

const salt = await bcrypt.genSalt(12)
const passwordHash = await bcrypt.hash(password, salt)

//user

const user = new User({
    name,
    password: passwordHash
})

try{

 await user.save()
 res.status(201).json({msg:"Usuario criado com sucesso"})

} catch(error){
    console.log(error)
    res.status(500).json({msg: 'Erro no servidor'})

}

})





//login
app.post('/auth/login', async(req,res)=>{

    const {name, password} = req.body
    
    //validação

    if(!name){
        return res.status(422).json({msg:"Login incorreto"})
    }
    if(!password){
        return res.status(422).json({msg:"Login incorreto"})
    }

      //checando se o usuario já existe
      const user = await User.findOne({name: name})

      if(!user){
          return res.status(404).json({msg:"usuario não encontrado"})
      }

      //checando se a  senha bate com a cadastrada
      const checkPassword = await bcrypt.compare(password, user.password)

      if(!checkPassword){
        return res.status(404).json({msg:"usuario não encontrado"})
      }

      try{

        const secret = process.env.SECRET

        const token = jwt.sign(
        {
         id: user._id,
        },
        secret,
        )

        res.status(200).json({msg: 'Autenticação realizada com sucesso', token})

      } catch(err) {
        console.log(error)

        res.status(500).json({msg: 'Erro no servidor'})
    

      }
})



const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS 

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.jv7fxll.mongodb.net/?retryWrites=true&w=majority`,

).then(()=>{
    app.listen(3000)
    console.log("conectou ao banco!")
}).catch((err) => console.log(err))


