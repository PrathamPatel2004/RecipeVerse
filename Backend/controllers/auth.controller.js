import { findUserByEmail, findUserByUsername, createUser, verifyUser, generateTokens, matchPassword } from '../services/auth.service.js';
import userModel from '../models/user.model.js';
import userTokenModel from '../models/userToken.model.js';
import crypto from "crypto";
import jwt from "jsonwebtoken";
import sendEmail from "../config/sendEmail.js";
import admin from '../config/firebaseAdmin.js';
import verifyEmailTemplate from "../utils/verifyEmailTemplate.util.js";

import dotenv from "dotenv";
dotenv.config();

export const signup = async (req, res) => {
    try {
        const { username, fullname, email, password } = req.body;

        if (!username || !fullname || !email || !password) {
            return res.status(400).json({ message: "Missing required fields" });
        }
        const existingUser = await findUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const { user, token } = await createUser({ username, fullname, email, password, verificationExpiresAt: new Date(Date.now() + 20 * 60 * 1000) });

        const verificationUrl = `${process.env.FRONTEND_URL}/auth/verify?verificationToken=${token}`;

        await sendEmail({
            sendTo: user.email,
            subject: "Verify Your Signup",
            html: verifyEmailTemplate(verificationUrl, user.fullname),
        })
        return res.status(200).json({ message: "User created successfully. Please verify your email." });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}

export const verifyEmailLink = async (req, res) => {
    try {
        const { verificationToken } = req.body;

        if (!verificationToken) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        const user = await verifyUser(verificationToken);

        await sendEmail({
            sendTo: user.email,
            subject: "Welcome to RecipeVerse",
            html: "Welcome to our world."
            // html: welcomeEmailTemplate(user.name),
        })
        return res.status(200).json({ message: "User verified successfully" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}

export const login = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if ((!email && !username) || !password) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        let user;

        if (email) {
            user = await userModel.findOne({ email }).select("+hashedPassword");
        } else {
            user = await userModel.findOne({ username }).select("+hashedPassword");
        }

        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }

        if (!user.verified) {
            return res.status(403).json({ message: "Email not verified" });
        }

        if (user.authProvider === "google" && !user.hashedPassword) {
            return res.status(400).json({
                message: "This account was created using Google. Please login with Google."
            });
        }

        await matchPassword({ user, password });

        const { accessToken, refreshToken } = await generateTokens(user);

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
            path: "/",
            maxAge: 1000 * 60 * 60 * 24 * 30,
        });

        await userModel.updateOne(
            { _id: user._id },
            { lastLoginAt: new Date() }
        );
        const safeUser = user.toObject();
        delete safeUser.hashedPassword;

        return res.json({
            success: true,
            message: "Login successful",
            accessToken,
            user: safeUser,
        });
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({ message: error.message || "Login failed" });
    }
};

export const verifyAccessToken = async (req, res) => {
    try {
        res.set("Cache-Control", "no-store");

        const authHeader = req.headers.authorization;
        const token = authHeader?.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : null;

        if (!token) return res.status(401).json({ message: "No token" });

        const decoded = jwt.verify(token, process.env.SECRET_KEY_ACCESS_TOKEN);
        const user = await userModel.findById(decoded.id).select("-hashedPassword");

        if (!user) return res.status(401).json({ message: "User not found" });

        return res.json({ success: true, user });
    } catch (err) {
        return res.status(401).json({ message: "Invalid token" });
    }
};

export const refreshAccessToken = async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({ message: 'No refresh token provided' });   
        }

        let decoded;
        try {
            decoded = jwt.verify(refreshToken, process.env.SECRET_KEY_REFRESH_TOKEN);
        } catch {
            return res.status(401).json({ message: "Refresh token expired" });
        }
        const hashed = crypto.createHash("sha256").update(refreshToken).digest("hex");

        const validateToken = await userTokenModel.findOne({ token: hashed, type: "Refresh" });
        if (!validateToken) return res.status(401).json({ message: "Invalid refresh token" });

        await validateToken.deleteOne();

        const user = await userModel.findById(decoded.id);

        if (!user) return res.status(401).json({ message: 'User not found' });

        const tokens = await generateTokens(user);

        res.cookie("refreshToken", tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", // true only on HTTPS
            sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
            path: "/",
            maxAge: 1000 * 60 * 60 * 24 * 30,}
        );
        return res.status(200).json({ message: 'Access token refreshed successfully', accessToken: tokens.accessToken });
    } catch (err) {
        res.status(500).json({ message: "Session expired" });
    }
}

export const logoutController = async (req, res) => {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: 'No refresh token provided, unable to logout' }); 
    }

    const hashed = crypto.createHash("sha256").update(refreshToken).digest("hex");
    await userTokenModel.deleteOne({ token: hashed, type: "Refresh" });

    res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: true,
        sameSite: "none",
    });
    return res.status(200).json({ message: "Logout successful" });
}

export const googleAuthController = async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) return res.status(401).json({ message: "No token provided" });
        const decoded = await admin.auth().verifyIdToken(token);

        const { email, name, uid, picture } = decoded;

        let user = await userModel.findOne({ email });

        if (!user) {
            user = await userModel.create({
                fullname: name,
                email,
                googleUid: uid,
                profilePic: picture,
                authProvider: "google",
                verified: true,
                lastLoginAt: new Date(),
            });

            const { accessToken, refreshToken } = await generateTokens(user);
            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
                path: "/",
                maxAge: 1000 * 60 * 60 * 24 * 30,}
            );

            await sendEmail({
                sendTo: user.email,
                subject: "Welcome to RecipeVerse",
                html: "Welcome to our world."
                // html: welcomeEmailTemplate(user.name),
            })
            return res.json({ success: true, message: "New user created and login successful, set your username to continue", user, accessToken, newUser: true });
        }

        const { accessToken, refreshToken} = await generateTokens(user);
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
            path: "/",
            maxAge: 1000 * 60 * 60 * 24 * 30,}
        );

        await userModel.updateOne({ _id: user._id }, { lastLoginAt: new Date() });
        return res.json({ success: true, message: "Login successful", user, accessToken });
    } catch (err) {
        console.error("Firebase verify failed:", err?.message || err);
        return res.status(401).json({ message: "Invalid Google token" });
    }
};

export const setUsername = async (req, res) => {
    try {
        const { username } = req.body;

        const user = await userModel.findByIdAndUpdate(req.user.id, { username });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        return res.json({ success: true, username: user.username, user });
    } catch (err) {
        res.status(500).json({ success: false, message: "Username not set" });
    }
};
