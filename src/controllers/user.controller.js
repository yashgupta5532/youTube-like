import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(400, "Invalid userId !");
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      ` error while generating accessAndRefreshToken ${error.message}`
    );
  }
};

export const registerUser = asyncHandler(async (req, res) => {
  //get user details from frontend
  //validate the email and other data
  //check for avatar and coverImages
  //upload them to cloudinary
  //create a user

  const { username, fullName, email, password } = req.body;

  if (
    [username, fullName, email, password].some((field) => field.trim() === "")
  ) {
    throw new ApiError(400, `${field} is required`);
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, `User with ${email} or ${username} already exists`);
  }

  const avatarLocalPath = req.files?.avatar[0].path;
  const coverImagePath = req.files?.coverImage[0].path;
  if (!avatarLocalPath) {
    throw new ApiError(400, "avatar file is required");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImagePath);

  if (!avatar) {
    throw new ApiError(400, "avatar file is required");
  }

  const createdUser = await User.create({
    fullName,
    username,
    email,
    password,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
  });

  const user = await User.findById(createdUser._id).select(
    "-password -refreshToken"
  );

  if (!user) {
    throw new ApiError(400, "Error while registering user");
  }

  return res
    .status(200)
    .json(new ApiResponse(200, user, "User registered successfully"));
});

export const loginUser = asyncHandler(async (req, res) => {
  //take email and password from frontend
  //validate email is in db and verify password
  //generate accessToken and refreshToken
  //save accessToken and refresToken in cookie and also save refreshToken in db
  const { username, email, password } = req.body;
  if (!username || !email) {
    throw new ApiError(400, "username or email is required");
  }
  if (!password) {
    throw new ApiError(400, "password is required");
  }

  const user = User.findOne({
    $or: [{ username }, { email }],
  });
  if (!user) {
    throw new ApiError(400, "User doesnot exist !");
  }
  const isPasswordValid = user.isPasswordMatch(password);
  if (!isPasswordValid) {
    throw new ApiError(400, "password is incorrect !");
  }

  const { accessToken, refreshToken } = generateAccessAndRefreshToken(user._id);

  const loggedInUser = await User.findById(user._id).select(
    "-password refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "User LoggedIn successfully"
      )
    );
});

export const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, null, "User logged out successfully"));
});

export const refreshAccessToken = asyncHandler(async (req, res) => {
  //get the refreshToken from cookie
  //verify refreshToken
  //find user by decodedToken
  //match incomingRefreshToken with db refreshToken
  //generate new accessAndRefreshToken
  //save into cookies

  const incomingRefreshToken =
    req.cookies?.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(403, "Unauthorised request");
  }

  const decodedToken = jwt.verify(
    incomingRefreshToken,
    process.env.RESET_TOKEN_SECRET
  );
  const user = await User.findById(decodedToken._id).select("-password");
  if (!user) {
    throw new ApiError(401, "Invalid refresh Token !");
  }
  if (user.refreshToken !== incomingRefreshToken) {
    throw new ApiError(401, "Refresh Token was used or has expired");
  }
  const { accessToken, refreshToken } = generateAccessAndRefreshToken(user._id);
  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { accessToken, refreshToken },
        "AccessToken is refreshed"
      )
    );
});

export const updatePassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  const user = await User.findById(req.user._id).select("-refreshToken");
  const isPasswordValid = await user.isPasswordMatch(oldPassword);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid oldPassword");
  }
  if (newPassword !== confirmPassword) {
    throw new ApiError(401, "new password and confirm password doesnot match");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });
  return res
    .status(200)
    .json(new ApiResponse(200, "Password changed successfully"));
});

export const getCurrentUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  return res
    .status(200)
    .json(new ApiResponse(200, user, "current user fetched successfully"));
});

export const updatedUserProfile = asyncHandler(async (req, res) => {
  const updatedUserField = req.body;
  const user = await User.findByIdAndUpdate(
    req.user._id,
    { $set: updatedUserField },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "User Profile updated"));
});

export const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path;
  if (!avatarLocalPath) {
    throw new ApiError(401, "avatar file is missing");
  }
  const avatar = await uploadOnCloudinary(avatarLocalPath);

  if (!avatar.url) {
    throw new ApiError(401, "Error while uploading avatar");
  }
  const user = await User.findById(
    req.user._id,
    {
      $set: {
        avatar: avatar.url,
      },
    },
    {
      new: true,
    }
  );
  return res
    .status(200)
    .json(new ApiResponse(200, user, "avatar updated successfully"));
});

export const updatedCoverImage = asyncHandler(async (req, res) => {
  const coverImagePath = req.file?.path;
  if (!coverImagePath) {
    throw new ApiError(401, "CoverImage file is missing");
  }

  const coverImage = await uploadOnCloudinary(coverImagePath);
  if (!coverImage.url) {
    throw new ApiError(401, "Error while uploading coverImage");
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        coverImage: coverImage.url,
      },
    },
    { new: true }
  ).select("-password -refreshToken")
  return res.status(200).json(
    new ApiResponse(200,user,"CoverImage updated successfully")
  )
});
