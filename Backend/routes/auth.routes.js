import { Router } from 'express';
import authMiddleware from '../middlewares/auth.middleware.js';
import { signup, verifyEmailLink, login, verifyAccessToken, refreshAccessToken, logoutController, googleAuthController, setUsername } from '../controllers/auth.controller.js';

const authRouter = Router();

authRouter.post("/signup", signup);
authRouter.post("/signup-verification", verifyEmailLink);
authRouter.post("/verify", authMiddleware, verifyAccessToken)
authRouter.post("/login", login);
authRouter.get("/refresh", refreshAccessToken);
authRouter.post("/logout", logoutController);
authRouter.post("/google", googleAuthController);
authRouter.put("/set-username", authMiddleware, setUsername);

export default authRouter;