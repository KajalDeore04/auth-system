import jwt from 'jsonwebtoken';

//decode userId from token
const userAuth = async (req, res, next) => {
    const {token} = req.cookies;

    if(!token){
        return res.json({success: false, message: "Unauthorized, Login again" });
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET)

        if(tokenDecode.id){
            req.body.userId = tokenDecode.id
        } else {
            return res.json({success: false, message: "Unauthorized, Login again" });
        }

        next();

    } catch (error) {
        return res.json({success: false, message: "Unauthorized, Login again" });
    }
}

export default userAuth;