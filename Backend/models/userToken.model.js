import mongoose from "mongoose";

const userTokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'user', index: true },
    type: { type: String, enum: ['Verify', 'Reset', 'Refresh'], required: true },
    token: { type: String, required: true, index: true },
    expiresAt: { type: Date, index: { expires: 0 } }
});

const userTokenModel = mongoose.model('userToken', userTokenSchema);

export default userTokenModel;