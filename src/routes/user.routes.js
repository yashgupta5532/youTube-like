import express from "express";
import { getCurrentUser, loginUser, logoutUser, refreshAccessToken, registerUser, updatePassword, updateUserAvatar, updatedCoverImage, updatedUserProfile } from "../controllers/user.controller.js";
import {upload } from "../middlewares/multer.middleware.js"
import { verifyJwt } from "../middlewares/auth.middleware.js";

const router = express.Router();

router.route("/register").post(
    upload.fields(
        {
            name:"avatar",
            maxCount:1
        },
        {
            name:"coverImage",
            maxCount:1
        }
    ),
    registerUser
    )

router.route("/login").post(loginUser);

router.route("/logout").post(verifyJwt,logoutUser);

router.route("/refresh-token").post(refreshAccessToken);

router.route("/change/password").put(verifyJwt,updatePassword);

router.route("/current-user").get(verifyJwt,getCurrentUser)

router.route("/updated/profile").put(verifyJwt,updatedUserProfile);

router.route("/updated/avatar").put(verifyJwt,upload.single("avatar"),updateUserAvatar);

router.route("/updated/coverImage").put(verifyJwt,upload.single("coverImage"),updatedCoverImage);

export default router;