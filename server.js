const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const userRoute = require("./routes/userRoute");
const errorHandler = require("./middleware/errorMiddleware");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();
// middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({extended: false}));
app.use(bodyParser.json());
app.use(
    cors({
        origin: ["http://localhost:3000"],
        credentials: true,
    })
)

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// routes middleware
app.use("/api/users", userRoute);

// routes
app.get("/", (req, res) => {
    res.send("home page");
});

// error middleware
app.use(errorHandler);
// connect to db and start server
const PORT = process.env.PORT || 5000;
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        app.listen(PORT, () => {
            console.log(`server running on port ${PORT}`);
        })
    })
    .catch((err) => console.log(err));