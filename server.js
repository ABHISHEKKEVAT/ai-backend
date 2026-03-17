require("dotenv").config();
const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");

const app = express();
connectDB();

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

app.use("/api/auth", require("./routes/auth"));
app.use("/api/users", require("./routes/user"));

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
