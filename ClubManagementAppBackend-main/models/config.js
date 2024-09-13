const mongoose = require("mongoose");

mongoose.connect("mongodb://0.0.0.0:27017/ClubManagement");

const db = mongoose.connection;

db.on("error", () => {
  console.log("Database Not Connected....");
});
db.once("open", () => {
  console.log("Database Connected Success....");
});
module.exports = db;