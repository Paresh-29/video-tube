import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { z } from "zod";

const userSchemaZod = {
  username: z.string().regex(/^[a-zA-Z0-9_.-]+$/),
  email: z
    .string()
    .email()
    .refine((data) => data.includes("@"), {
      message: 'Email must include "@"',
    }),
  fullName: z.string().regex(/^[a-zA-Z\s]+$/),
  password: z
    .string()
    .min(8)
};

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowerCase: true,
      trim: true,
      index: true,
      validate: {
        validator: (value) => userSchemaZod.username.safeParse(value).success,
        message:
          "Username can only contain letters, numbers, underscores, dots, and hyphens..",
      },
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowerCase: true,
      trim: true,
      validate: {
        validator: (value) => userSchemaZod.email.safeParse(value).success,
        message: 'Email must include "@"',
      },
    },
    fullName: {
      type: String,
      required: true,
      trim: true,
      index: true,
      validate: {
        validator: (value) => userSchemaZod.fullName.safeParse(value).success,
        message: "Full name can only contain letters and spaces.",
      },
    },
    avatar: {
      type: String, //cloudinary url
      required: true,
    },
    coverImage: {
      type: String,
    },
    watchHistory: [
      {
        type: Schema.Types.ObjectId,
        ref: "Video",
      },
    ],
    password: {
      type: String,
      required: [true, "Password is required"],
      validate: {
        validator: (value) => userSchemaZod.password.safeParse(value).success,
        message:
          "Password must be at least 8 characters long and include at least one lowercase letter, one uppercase letter, and one digit.",
      },
    },
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullName: this.fullName,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

export const User = mongoose.model("User", userSchema);
