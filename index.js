const jwt = require('jsonwebtoken');
const validate = require('validate.js');
const Encryption = require('mk-encryption');

let secretJWT;
let cipher;
let transformId;
let initialized = false;

function setup(secretJwtPass, encryptionPass, {transformIdFn = (id)=>id}) {
    if(!secretJwtPass || !encryptionPass) throw 'Your must provide secretJwtPass and encryptionPass';
    secretJWT = secretJwtPass;
    cipher = new Encryption(encryptionPass);
    transformId = transformIdFn;
    initialized = true;
}

function generateToken(id, role, data = {}, version = "1", expire = '30d') {
    if(!initialized) throw 'You must setup mk-token before use it';
    return cipher.encrypt(jwt.sign({...data, id, role, version}, secretJWT, {expiresIn: expire}))
}

function validateToken(bearer, version = "1") {
    if(!initialized) throw 'You must setup mk-token before use it';
    if (!bearer) throw 'No bearer provided';
    let decryptedBearer = cipher.decrypt(bearer.replace('Bearer ', ''));
    let payload = jwt.verify(decryptedBearer, secretJWT);
    if (validate(payload, {
        role: {presence: true},
        id: {presence: true},
    })) throw 'Unauthorized';
    if (payload.iat >= payload.exp || payload.version !== version) throw 'Unauthorized';
    if(transformId) payload._id = transformId(payload.id);
    return payload;
}

module.exports = {generateToken, validateToken, setup};