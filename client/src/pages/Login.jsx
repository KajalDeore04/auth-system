import React, { useContext, useState } from 'react';
import {assets} from '../assets/assets.js'
import { useNavigate } from 'react-router-dom';
import { AppContext } from '../context/AppContext.jsx';
import axios from 'axios';
import { toast } from 'react-toastify';

const Login = () => {

    const navigate = useNavigate()

    const {backendUrl, setIsLoggedin, getUserData} = useContext(AppContext)

    const [state, setState] = useState('Sign Up')
    const [name, setName] = useState('')
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')

    const onSubmitHandler = async (e) => {
        try {
            e.preventDefault()

            // to send the cookie
            axios.defaults.withCredentials = true

            // api call request and sending deets
            if (state === 'Sign Up'){
                const {data} = await axios.post(backendUrl + '/api/auth/register', {email, name, password})

                if (data.success){
                    setIsLoggedin(true)
                    getUserData()                    
                    navigate('/')
                } else {
                    toast.error(error.message)
                }
            } else {
                const {data} = await axios.post(backendUrl + '/api/auth/login', {email, password})

                if (data.success){
                    setIsLoggedin(true)
                    getUserData()
                    navigate('/')
                } else {
                    toast.error(error.message)
                }
            }
        } catch (error) {
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
            <div className='bg-slate-900 p-10 rounded-lg w-full shadow-lg sm:w-96 text-indigo-300 text-sm'>

                <h2 className='text-3xl font-semibold text-white text-center mb-3 '>{state === 'Sign Up' ? 'Sign Up' : 'Login'}</h2>
                <p className='text-center text-sm mb-6 '>{state === 'Sign Up' ? 'Create your account' : 'Login to your account!'}</p>

                <form onSubmit={onSubmitHandler}>
                    {state === 'Sign Up' && (
                        <div className='mb-4 w-full px-5 py-2.5 rounded-full bg-[#333a5c] flex items-center gap-3'>
                            <img src={assets.person_icon} alt="user" />
                            <input 
                                onChange={(e)=> setName(e.target.value)} value={name} 
                                type="text" 
                                placeholder='Full Name' 
                                required 
                                className='bg-transparent outline-none'/>
                        </div>
                    )}
                    
                    <div className='mb-4 w-full px-5 py-2.5 rounded-full bg-[#333a5c] flex items-center gap-3'>
                        <img src={assets.mail_icon} alt="user" />
                        <input 
                            onChange={(e)=> setEmail(e.target.value)} value={email} 
                            type="email" 
                            placeholder='Email id' 
                            required 
                            className='bg-transparent outline-none'/>
                    </div>
                    <div className='mb-4 w-full px-5 py-2.5 rounded-full bg-[#333a5c] flex items-center gap-3'>
                        <img src={assets.lock_icon} alt="user" />
                        <input 
                            onChange={(e)=> setPassword(e.target.value)} value={password} 
                            type="password" 
                            placeholder='Password' 
                            required 
                            className='bg-transparent outline-none'/>
                    </div>

                    {state === 'Login' && (
                    <p onClick={() => navigate('/reset-password')} className='mb-4 text-indigo-500 cursor-pointer'>Forgot Password?</p>)}

                    <button className='w-full py-2.5 rounded-full bg-gradient-to-r from-indigo-500 to-indigo-900 text-white font-medium'>{state}</button>
                </form>


                {state === 'Sign Up' ? (
                    <p className='text-center text-sm mt-4 text-gray-400'>Already have an account?{' '}
                        <span 
                        onClick={() => setState('Login')} className='text-blue-400 cursor-pointer underline '>Login Here
                        </span>
                    </p>
                ) : (
                    <p className='text-center text-sm mt-4 text-gray-400'>Dont have an account?{' '}
                        <span 
                            onClick={() => setState('Sign Up')} className='text-blue-400 cursor-pointer underline '>Sign Up
                        </span>
                    </p>
                )}

                 
            </div>
        </div>
    );
}

export default Login;
