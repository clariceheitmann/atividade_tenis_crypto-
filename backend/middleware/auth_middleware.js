const cryptoJs = require('crypto-js')
const CHAVE_SECRETA = 'segredo'

function authMiddleware(req,res,next){
    const token = req.headers['authorization']

    // Verifica se o usuário enviou um token
    if(!token){
        return res.status(401).json({message: 'Acesso negado, realize o login!'})
    }

    try{
        // Descriptografa o token utilizando a chave secreta
        const bytes = cryptoJs.AES.decrypt(token, CHAVE_SECRETA)
        // Converte os dados descriptografados para texto
        const dadosDescriptografados = bytes.toString(cryptoJs.enc.Utf8)

        // Verifica se foi possível obter os dados do token
        if(!dadosDescriptografados){
            return res.status(403).json({message: 'Acesso proibido!'})
        }

        // Converte os dados do token de JSON para um objeto JavaScript
        const payload = JSON.parse(dadosDescriptografados)

        // Verifica se o tempo de validade da sessão já terminou
        if(Date.now() > payload.expiraEm){
            return res.status(401).json({message: 'Sessão expirada, realize o login!'})
        }

        req.usuario = payload
        next()

    }catch(err){
        console.error('Falha na autenticação!',err)
        return res.status(401).json({message: 'Falha na autenticação!'})
    }
}

module.exports = authMiddleware