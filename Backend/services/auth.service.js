import bcryptjs from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import userModel from '../models/user.model.js';
import userTokenModel from '../models/userToken.model.js';

export const findUserByEmail = async (email) => {
    const user = await userModel.findOne({ email });
    return user;
}

export const findUserByUsername = async (username) => {
    const user = await userModel.findOne({ username });
    return user;
}

export const createUser = async ({ username, fullname, email, password }) => {
    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = password ? await bcryptjs.hash(password, salt) : null;

    const user = await userModel.create({
        username,
        fullname,
        email,
        hashedPassword,
        authProvider: 'local',
    });

    const token = crypto.randomBytes(32).toString('hex');
    const verificationToken = crypto.createHash('sha256').update(token).digest('hex');
    await userTokenModel.create({ userId: user._id, token: verificationToken, type: 'Verify', expiresAt: new Date(Date.now() + 60 * 15 * 1000) });

    return { user, token };
}

export const verifyUser = async (verificationToken) => {
    const hashedToken = crypto.createHash('sha256').update(verificationToken).digest('hex');

    const userToken = await userTokenModel.findOne({ token: hashedToken, type: 'Verify' });

    const user = await userModel.findById(userToken.userId);
    if (!userToken) throw new Error("Invalid token");

    await userModel.findByIdAndUpdate(userToken.userId, { verified: true });
    await userToken.deleteOne();

    return user;
}

export const generateTokens = async (user) => {
    const accessToken = jwt.sign({ id: user._id, email: user.email }, process.env.SECRET_KEY_ACCESS_TOKEN, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id, email: user.email }, process.env.SECRET_KEY_REFRESH_TOKEN, { expiresIn: '30d' });

    const hashedRefreshToken = crypto.createHash("sha256").update(refreshToken).digest("hex");

    await userTokenModel.create({
        userId: user._id,
        token: hashedRefreshToken,
        type: "Refresh",
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
    return { accessToken, refreshToken };
}

export const matchPassword = async ({ user, password }) => {
    if (!user?.hashedPassword) {
        throw new Error("This account uses Google login. Please continue with Google.");
    }

    const isMatch = await bcryptjs.compare(password, user.hashedPassword);
    if (!isMatch) throw new Error("Invalid credentials");
    return true;
};