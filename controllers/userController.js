const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

// generate token
const generateToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {expiresIn: "1d"});
};

// register user
const registerUser = asyncHandler(async(req, res) =>{
    const {name, email, password} = req.body;

    // validation
    if(!name || !email || !password){
        res.status(400);
        throw new Error("please fill in all requird fields");
    }
    if(password.length < 6){
        res.status(400);
        throw new Error("password must be up to 6 characters");
    }

    // check if user email already exists
    const userExists = await User.findOne({email});

    if(userExists){
        res.status(400);
        throw new Error("email has already been registered");
    }

    // create new user
    const user = await User.create({ 
        name,
        email,
        password,
    })

    // generate token
    const token = generateToken(user._id);

    // send HTTP-only cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        // sameSite: "none",
        // secure: true
    });
    if(user){
        const {_id, name, email, photo, phone, bio} = user;
        res.status(201).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            token
        })
    } else {
        res.status(400);
        throw new Error("invalid user data");
    }
})

// login user
const loginUser = asyncHandler(async(req, res) => {
    const {email, password} = req.body;

    // validate request
    if(!email || !password){
        res.status(400);
        throw new Error("please add email and password")
    }

    // check if user exists
    const user = await User.findOne({email});

    if(!user){
        res.status(400);
        throw new Error("user not found, please signup");
    }

    // user exists, check if password is correct
    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    // generate token
    const token = generateToken(user._id);

    if(passwordIsCorrect){
        // send http-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            // sameSite: "none",
            // secure: true,
        })
    }
    if(user && passwordIsCorrect) {
        const {_id, name, email, photo, phone, bio} = user;
        res.status(200).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            token
        })
    }else{
        res.status(400);
        throw new Error("invalid email or password")
    }
})

// logout user
const logout = asyncHandler(async(req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true,
    });
    return res.status(200).json({message: "successfully logged out"});
})

// get user data
const getUser = asyncHandler(async(req, res) => {
    const user = await User.findById(req.user._id);
    if(user){
        const {_id, name, email, photo, phone, bio} = user;
        res.status(200).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
        })
    }else{
        res.status(400);
        throw new Error("user not found");
    }
})

// get login status
const loginStatus = asyncHandler(async(req, res) => {
    const token = req.cookies.token;
    if(!token) {
        return res.json(false);
    }
    // verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if(verified) {
        return res.json(true);
    }
    return res.json(false);
})

// update user
const updateUser = asyncHandler(async(req, res) => {
    const user = await User.findById(req.user._id);

    if(user) {
        const {name, email, photo, phone, bio} = user;
        user.email = email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;
        user.photo = req.body.photo || photo;

        const updateUser = await user.save();
        res.status(200).json({
            _id: updateUser._id,
            name: updateUser.name,
            email: updateUser.email,
            photo: updateUser.photo,
            phone: updateUser.phone,
            bio: updateUser.bio,
        })
    } else {
        res.status(404);
        throw new Error("user not found");
    }
})

// change password
const changePassword = asyncHandler(async(req, res) => {
    const user = await User.findById(req.user._id);
    const {oldPassword, password} = req.body;

    if(!user) {
        res.status(400);
        throw new Error("user not found, please signup");
    }
    // validate
    if(!oldPassword || !password) {
        res.status(400);
        throw new Error("please add old and new password");
    }
    // check if old password matches password in db
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    // save new password
    if(user && passwordIsCorrect){
        user.password = password;
        await user.save();
        res.status(200).send("password change successful");
    }else {
        res.status(400);
        throw new Error("old password is incorrect");
    }   
})

// forgot password
// ------------------we have to run this in form of thunder client unless it would not work...
// use 'form' to post email
const forgotPassword = asyncHandler(async (req, res) => {
    const {email} = req.body;
    const user = await User.findOne(email)
    if(!user) {
        res.status(404)
        throw new Error("user does not exist")
    }

    // delete token ifit exists in db
    let token = await Token.findOne({userId: user._id})
    if(token){
        await token.deleteOne()
    }
    // create reset token
    let resetToken = crypto.randomBytes(32).toString("hex") + user._id
    console.log(resetToken) // it is essential to use when we are using thunder client for reset password

    // hash token before saving to db
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex")
    // console.log(hashedToken)

    // save token to db
    await new Token({
        userId: user._id,
        token: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * (60 * 1000) // thirty minutes
    }).save()

    // construct reset url
    const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`

    // reset email
    const message = `
        <h2>Hello ${user.name}</h2>
        <p>Please use the url below to reset your password</p>
        <p>this reset link is valid for only thirty minutes.</p>
        <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
        <p>Regards...</p>
        <p>Pinvent Team</p>
    `;
    const subject = 'password reset request'
    const send_to = user.email
    const sent_from = process.env.EMAIL_USER

    try{
        await sendEmail(subject, message, send_to, sent_from)
        res.status(200).json({success: true, message: "reset email sent"})
    }catch(error){
        res.status(500)
        throw new Error("email not sent, please try again")
    }
})

// reset password
const resetPassword = asyncHandler(async (req, res) => {
    const {password} = req.body;
    const {resetToken} = req.params;

    // hash token, then compare to token in db
    const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

    // find token in db
    const userToken = await Token.findOne({
        token: hashedToken,
        expiresAt: {$gt: Date.now()}
    })
    if(!userToken){
        res.status(404);
        throw new Error("invalid or expired token");
    }
    // find user
    const user = await User.findOne({_id: userToken.userId})
    user.password = password;
    await user.save();
    res.status(200).json({
        message: "password reset successful, please login"
    })
})


module.exports = {
    registerUser,
    loginUser,
    logout,
    getUser,
    loginStatus,
    updateUser,
    changePassword,
    forgotPassword,
    resetPassword
}