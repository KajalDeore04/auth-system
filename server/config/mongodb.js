import mongoose from "mongoose";

const connectDB = async () => {

    //print when connection is on
    mongoose.connection.on('connected', () => {
        console.log("Database connected");
    })
    await mongoose.connect(`${process.env.MONGODB_URI}/auth-system`)
}

export default connectDB;