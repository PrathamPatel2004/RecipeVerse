import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username : { type : String, unique : true, minlength : 3, index: true },
    fullname : { type : String, minlength : 3 },
    email : { type : String, required : true, unique : true, lowercase : true, index : true },
    hashedPassword : { type : String, select : false },
    verified : { type : Boolean, default : false, index : true },
    authProvider: { type : String, enum : ["local", "google"], default : "local" },
    googleUid : { type : String, default : null },
    profilePic : { type : String, default : '' },
    role : { type : String, enum : ['Nutritionist', 'Professional Cook', 'User'], default : 'User', index : true },
    lastLoginAt : { type : Date, default : null }
}, { timestamps: true });

userSchema.index({ username : 1, verified : 1 });
userSchema.index({ email : 1, verified : 1 });
const userModel = mongoose.model("user", userSchema);

export default userModel;