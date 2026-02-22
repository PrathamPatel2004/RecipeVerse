import jwt from 'jsonwebtoken';

const getTokenFromRequest = (req) => {
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) return authHeader.split(' ')[1];
    return null;
}

const authMiddleware = (req, res, next) => {
    try{
        const token = getTokenFromRequest(req);

        if (!token) return res.status(401).json({ message: "Unauthorized. Token not found.", error: true, success: false });
        
        const decoded = jwt.verify(token, process.env.SECRET_KEY_ACCESS_TOKEN);

        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({
            message: 
                err.name === 'TokenExpiredError'
                    ? 'Unauthorized. Token has expired.'
                    : 'Unauthorized. Invalid token.',
            error: true,
            success: false
        })
    }
}

export default authMiddleware;