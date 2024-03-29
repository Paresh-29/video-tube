import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUDNAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async (localFilePath) => {
  try {
    if (!localFilePath) {
      return null;
    }
    //upload the file on cloudinary
    const response = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });
    //file has been uploaded successfully
    // console.log("file is uploaded on cloudinary", response.url);
    // return response;
    fs.unlinkSync(localFilePath);
    return response;
  } catch (error) {
    console.log("Error in uploading in Cloudinary", error);
    fs.unlinkSync(localFilePath); //remove the locally save temp file as the upload opertion got failed
    return null;
  }
};

export { uploadOnCloudinary };
