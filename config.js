import dotenv from "dotenv";
dotenv.config();

export const config = {
  IS_DEV_ENV: process.env.NODE_ENV === "development",
};