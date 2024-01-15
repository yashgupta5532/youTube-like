import dotenv from "dotenv";
import express from "express";
import connectDB from "./db/index.js";

dotenv.config({
  path: "./env",
});

const app =express();
const port =process.env.PORT;
connectDB()
.then(()=>{
    app.listen(port,()=>{
        console.log(`App is listening on port ${port}`)
    })
    app.on("error",()=>{
        console.log("Error on app ",error)
        throw error
    })
})
.catch((error)=>{
    console.log(`Mongodb failed to connect ${error}`)
})

