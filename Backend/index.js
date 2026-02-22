import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import dotenv from 'dotenv';
dotenv.config();

import connectDB from './config/connectDB.js';
import authRouter from './routes/auth.routes.js';

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
    credentials: true,
    origin: process.env.FRONTEND_URL
}));

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    res.send({ message: "Backend is running on port " + PORT });  
})

app.use('/api/auth', authRouter);

connectDB().then(() => {
    app.listen(PORT, () => console.log("Server is running on port " + PORT));
});