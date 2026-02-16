import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    userName: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
    hashedPassword: { type: String, required: true },
}, { timestamps: true });

const userModel = mongoose.model("user", userSchema);

export default userModel;