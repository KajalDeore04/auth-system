import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import {EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE} from '../config/emailTemplates.js';

export const register = async (req, res) => {
    const {name, email, password} = req.body;

    // check the form deets
    if (!name || !email || !password) {
        return res.json({success: false, message: "Please enter all the details"})
    }

    try {
        // check if exists using email
        const existingUser = await userModel.findOne({email})
        if(existingUser){
            return res.json({success: false, message: "User already exists"})
        }

        // doesn't exist then create user model, insert deets and save
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({name, email, password: hashedPassword})
        await user.save();

        //saved, generate token
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        //add token in cookie
        res.cookie('token', token,{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7*24*60*60*1000 // 7 days into millisec
        })


        // send welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Kajals Portfolio',
            text: `Welcome to out website. Your account has been created with email id: ${email} `
        }
        await transporter.sendMail(mailOptions);


        return res.json({success: true})

    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

/*----------------------------LOGIN---------------------------------- */


export const login = async (req, res) => {
    const {email, password} = req.body;

    if(!email ||!password){
        return res.json({success:false, message: "Please enter both email and password"})
    }

    try {
        const user = await userModel.findOne({email})

        if(!user){
            return res.json({success: false , message: "User not found"})
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch){
            return res.json({success: false, message: "Incorrect password"})
        }

        // generate token using mongodb user id
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        //add token in cookie
        res.cookie('token', token,{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7*24*60*60*1000 // 7 days into ms
        })

        return res.json({success: true})


    } catch (error) {
        return res.json({success: false, message:error.message})
    }
}


/*-------------------------LOG OUT------------------------------------ */

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

        return res.json({success: true, message: "Logged Out"})
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}


/*-------------------------Send OTP--------------------------------- */
//send otp to user
//userId is fetched from token 
export const sendVerifyOTP = async (req, res) => {
    try {
        const {userId} = req.body;
        const user = await userModel.findById(userId);

        // already verified
        if(user.isAccountVerified){
            return res.json({success: false, message: "Account is already verified"})
        }

        // gen,expire, save otp
        const otp = String(Math.floor(100000 + Math.random() * 900000))
        user.verifyOTP = otp;
        user.verifyOTPExpireAt = Date.now() + 24 * 60 * 60 * 1000

        await user.save();

        //verification mail
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            // text: `Your OTP is ${otp}. Verify your account using this OTP. `,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        }
        await transporter.sendMail(mailOptions);

        res.json({success: true, message: 'Verification OTP sent on your email'})

        
    } catch (error) {
         res.json({success: false, message: error.message})
    }
}

/*-------------------------Check OTP--------------------------------- */

export const verifyEmail = async (req, res) => {
    const {userId, otp} = req.body
    
    if(!userId || !otp){
        return res.json({success: false, message: "Missing Details"})
    }

    try {
        const user = await userModel.findById(userId)

        if(!user){
            return res.json({success: false, message: "User not found"})
        }

        if(user.verifyOTP === '' || user.verifyOTP !== otp){
            return res.json({success: false, message: "Invalid OTP"})
        }

        if(user.verifyOTPExpireAt < Date.now()){
            return res.json({success: false, message: "OTP Expired"})
        }

        // reset
        user.isVerified = true;
        user.verifyOTP = '';
        user.verifyOTPExpireAt = 0;

        await user.save();
        return res.json({success: true, message: "Email verified successfully"})


    } catch (error) {
        return res.json({success: false, message: "Missing Details"})
    }
}


/*-----------------Auth user--------------------------------- */
// other will be handled by middleware
export const isAuthenticated = async (req, res) => {
    try {
        return res.json({success: true})
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}


// send password reset OTP
export const sendResetOTP = async (req, res) => {
    const {email} = req.body
    if(!email){
        return res.json({success: false, message: "Email is required"})
    }

    try {
        const user = await userModel.findOne({email})

        if(!user){
            return res.json({success: false, message: "User not found"})
        } 

        const otp = String(Math.floor(100000 + Math.random() * 900000))
        user.resetOTP = otp;
        user.resetOTPExpireAt = Date.now() + 15 * 60 * 1000 //15 mins

        await user.save();

        //verification mail
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password. `,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
        }
        await transporter.sendMail(mailOptions);

        res.json({success: true, message: 'OTP sent to your email'})


    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}


// set new password
export const resetPassword = async (req, res) => {
    const {email, otp, newPassword} = req.body

    if(!email || !otp || !newPassword){
        return res.json({success: false, message: "All fields are required"})
    }

    try {
        const user = await userModel.findOne({email})
        if(!user){
            return res.json({success: false, message: "User not found"})
        }

        if(user.resetOTP === '' || user.resetOTP !== otp){
            return res.json({success: false, message: "Invalid OTP"})
        }

        if(user.resetOTPExpireAt < Date.now()){
            return res.json({success: false, message: "OTP has expired"})
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        user.password = hashedPassword;
        user.resetOTP = '';
        user.resetOTPExpireAt = 0;

        await user.save();
        return res.json({success: true, message: 'Password reset successfully'})
        
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}