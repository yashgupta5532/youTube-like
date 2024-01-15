import { ApiError } from "../utils/ApiError";
import { asyncHandler } from "../utils/asyncHandler";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model";

export const verifyJwt=asyncHandler(async (req,_,next)=>{
    try {
        const token=req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","");
    
        if(!token){
            throw new ApiError(403,"Unauthorised request");
        }
        const decodedTokenInfo=jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
        const user=User.findById(decodedTokenInfo._id).select("-password -refreshToken")
    
        if(!user){
            throw new ApiError(403,"Invalid access Token")
        }
        req.user=user;
        next();
    } catch (error) {
        throw new ApiError(500,error?.message || "Invalid access Token");
    }


})