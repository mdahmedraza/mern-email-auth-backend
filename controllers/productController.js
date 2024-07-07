const asyncHandler = require("express-async-handler");
const Product = require("../models/productModel");
const {fileSizeFormatter} = require("../utils/fileUpload");
const cloudinary = require("cloudinary").v2;

// create product
const createProduct = asyncHandler(async (req, res) => {
    const {name, sku, category, quantity, price, description} = req.body;

    // validation
    if(!name || !category || !quantity || !price || !description) {
        res.status(400);
        throw new Error("please fill in all fields");
    }

    // handle image upload
    let fileData = {};
    if(req.file) {
        // save image to cloudinary
        let uploadedFile;
        try{
            uploadedFile = await cloudinary.uploader.upload(req.file.path, {
                folder: "pinvent app",
                resource_type: "image"
            })
        } catch (error) {
            res.status(500);
            throw new Error("image could not be uploaded");
        }
        fileData = {
            fileName: req.file.originalname,
            filePath: uploadedFile.secure_url,
            fileType: req.file.mimetype,
            fileSize: fileSizeFormatter(req.file.size, 2)
        }
    }
})