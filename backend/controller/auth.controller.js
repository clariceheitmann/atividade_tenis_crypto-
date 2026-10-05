const Usuario = require('../models/Usuario')

// Importanto da biblioteca crypto-js
const cryptoJs = require('crypto-js')
const CHAVE_SECRETA = 'segredo'

const login = async(req,res) =>{
    const valores = req.body 

    if(!valores.email || !valores.senha){
        return res.status(400).json({message: 'Preencha os campos de email e senha!'})
    }

    try{
        const usuario = await Usuario.findOne({where: {email: valores.email}})

        if(!usuario){
            return res.status(404).json({message: 'Usuário não encontrado!'})
        }

        // Descriptografa a senha armazenada no banco de dados
        const bytes = cryptoJs.AES.decrypt(usuario.senha, CHAVE_SECRETA)
        // Converte a senha descriptografada para texto
        const senha = bytes.toString(cryptoJs.enc.Utf8)

        // Verifica se a senha está correta 
        if(valores.senha !== senha){
            return res.status(401).json({message: 'Senha incorreta!'})
        }

        //Definindo 1 hora e meia como tempo de expiração
        const noventaMinutosEmMs = 1.5 * 60 * 60 * 1000
        const expiraEm = Date.now() + noventaMinutosEmMs

        // Cria os dados que serão armazenados dentro do token
        const payload = {
            idUsuario: usuario.codUsuario,
            nome: usuario.nome,
            expiraEm: expiraEm
        }

        const token = cryptoJs.AES.encrypt(JSON.stringify(payload), CHAVE_SECRETA).toString()

        return res.status(200).json({
            message: 'Login realizado com sucesso!',
            nome: usuario.nome,
            token: token
        })

    }catch(err){
        console.error('Erro ao realizar o login!',err)
        res.status(500).json({message: 'Erro ao realizar o login!'})
    }
}

module.exports = { login }
