express - to build
cors - to connect frontend to backend
dotenv - to store env variables
nodemon - auto-restart backend
jwt - to create token
mongoose - to connect with db
bcryptjs - to encrypt the password
nodemailer - to send email
cookie-parser - to send the cookies in the api response

NODE_ENV helps control the security related to the cookie/token
website work on https if PRODUCTION else on http if DEVELOPEMENT 

sameSite = use strict when we are local coz server and client are on same domain  but when we are hosted then domain could be different