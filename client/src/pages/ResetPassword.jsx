import React, { useState, useRef, useContext } from 'react';
import {assets} from '../assets/assets'
import {useNavigate} from 'react-router-dom';
import { AppContext } from '../context/AppContext';
import axios from 'axios';
import { toast } from 'react-toastify';

const ResetPassword = () => {

    const {backendUrl} = useContext(AppContext)

    axios.defaults.withCredentials = true

    const navigate = useNavigate();
    const [email, setEmail] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [isEmailSent, setIsEmailSent] = useState(false);
    const [otp, setOtp] = useState(0);
    const [isOtpSubmitted, setIsOtpSubmitted] = useState(false);


    const inputRefs = useRef([])

    // moves the pointer to next ip field
    const handleInput = (e, index) => {
        if (e.target.value.length > 0 && index < inputRefs.current.length - 1) {
            inputRefs.current[index + 1].focus();
        }
    };

    // moves cursor back to previous ip field
    const handleKeyDown = (e, index) => {
        if (e.key === 'Backspace' && e.target.value === '' && index > 0) {
            inputRefs.current[index-1].focus();
        }
    }

    // if otp is pasted then each digit on sep ip field
    const handlePaste = (e, index) => {
        const paste = e.clipboardData.getData('text')
        const pasteArray = paste.split('')

        pasteArray.forEach((char, index) => {
            if(inputRefs.current[index]){
                inputRefs.current[index].value = char
            }
        });
    }


    const onSubmitEmail = async (e) => {
        e.preventDefault();
        try {
            const {data} = await axios.post(`${backendUrl}/api/auth/send-reset-otp`, {email})
            data.success ? toast.success(data.message) : toast.error(data.message)

            data.success && setIsEmailSent(true) 
        } catch (error) {
            toast.error(error.message)
        }
    }


    const onSubmitOTP = async (e) => {
        e.preventDefault();
        const otpArray = inputRefs.current.map((e) => e.value)
        setOtp(otpArray.join(''))
        setIsOtpSubmitted(true)
    }

    const onSubmitNewPassword = async (e) => {
        e.preventDefault();
        try {
            const {data} = await axios.post(`${backendUrl}/api/auth/reset-password`,{email,otp,newPassword})

            data.success ? toast.success(data.message) : toast.error(data.message)

            data.success && navigate('/login')
        } catch {
            toast.error(error.message)
        }
    }



    return (
        <div className='flex items-center justify-center min-h-screen px-6 sm:px-0 bg-gradient-to-br from-blue-200 to-purple-400'>
            <img 
            src={assets.logo} 
            alt="" 
            onClick={() => navigate('/')}
            className='absolute top-5 left-5 sm:left-20 w-28 sm:w-32 cursor-pointer'/>

        {!isEmailSent && 

            <form onSubmit={onSubmitEmail} className='bg-slate-900 p-8 rounded-lg w-96 text-sm shadow-lg'>
                <h1 className='text-white text-2xl font-semibold text-center mb-4'>Reset Password</h1>
                <p className='text-center mb-6 text-indigo-300'>Enter your registered email id.</p>

                <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333a5c]'>
                    <img src={assets.mail_icon} alt="" className='w-3 h-3'/>
                    <input 
                    onChange={(e) => setEmail(e.target.value)} type="email" 
                    value={email}
                    required 
                    placeholder='Email id' 
                    className='bg-transparent outline-none text-white'/>
                </div>

                <button className='w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 text-white rounded-full mt-3'>Submit</button>
            </form>
        } 

        {!isOtpSubmitted && isEmailSent && 
            <form onSubmit={onSubmitOTP} className='bg-slate-900 p-8 rounded-lg w-96 text-sm shadow-lg'>
                <h1 className='text-white text-2xl font-semibold text-center mb-4'>Reset Password OTP</h1>
                <p className='text-center mb-6 text-indigo-300'>Enter the 6 digit code sent to your email id.</p>

                <div onPaste={handlePaste} className='flex justify-between mb-8'>
                    {Array(6).fill(0).map((_, index)=>(
                        <input
                        ref={(e) => inputRefs.current[index] = e}
                        onInput={(e) => handleInput(e, index)} 
                        onKeyDown={(e) => handleKeyDown(e, index)}
                        type="text" 
                        maxLength='1' 
                        key={index} 
                        required
                        className='w-12 h-12 bg-[#333a5c] text-white text-center text-xl rounded-md'/>
                    ))}
                </div>

                <button className='w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 text-white rounded-full'>Submit</button>
            </form> 
        }


        {isOtpSubmitted && isEmailSent &&
            
            <form onSubmit={onSubmitNewPassword} className='bg-slate-900 p-8 rounded-lg w-96 text-sm shadow-lg'>
                <h1 className='text-white text-2xl font-semibold text-center mb-4'>New Password</h1>
                <p className='text-center mb-6 text-indigo-300'>Enter the new Password below</p>

                <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333a5c]'>
                    <img src={assets.lock_icon} alt="" className='w-3 h-3'/>
                    <input 
                    onChange={(e) => setNewPassword(e.target.value)} type="password" 
                    value={newPassword}
                    required 
                    placeholder='Password' 
                    className='bg-transparent outline-none text-white'/>
                </div>

                <button className='w-full py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-900 text-white rounded-full mt-3'>Submit</button>
            </form>
        }

        </div>
    );
}

export default ResetPassword;
