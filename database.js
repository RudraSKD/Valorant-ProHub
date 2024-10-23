const express = require("express");
const app = express();
const argon2 = require('argon2');
const http=require('http').Server(app);
const bodyParser = require("body-parser");
const cors = require("cors")
const path = require("path");

const mysql = require("mysql2");
const db = mysql.createConnection({
    host:'localhost',
    user:'Rudra',
    password:'0599',
    database:'valorant_pro'
});

app.use(cors())
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, "public")));
app.get("/signin", function(req, res){
    res.sendFile(path.join(__dirname,"public","loginsignin.html"));
});
app.get("/login", function(req, res){
    res.sendFile(path.join(__dirname,"public","loginsignin.html"));
});
app.get("/index", function(req, res){
    res.sendFile(path.join(__dirname,"public","index.html"));
});
app.get("/forget", function(req, res){
    res.sendFile(path.join(__dirname, "public","loginsignin.html"));
});
app.get("/subscription", function(req,res){
    res.sendFile(path.join(__dirname, "public","subscription.html"));
});

db.connect(function(err){
    if (err)throw err;
    console.log("Connected to database");
});
  
app.post("/signinForm", function(req, res){
    const { uemail, uname, npassword, phnumber, recovery} = req.body;

    const queryCheckUser = 'SELECT * FROM user WHERE username = ?';
    db.query(queryCheckUser, [uname], async (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).send("Internal Server Error");
        }

        if (results.length > 0) {
            return res.status(409).json({ success: false, message: "User already exists. Please choose another username." });
        }
        try {
            const hash1 = await argon2.hash(npassword);
            const hash2 = await argon2.hash(recovery);
            const query = "INSERT INTO user (username, email, npassword, Phone, recovery) VALUES (?,?,?,?,?)";
            db.query(query, [uname, uemail, hash1, phnumber, hash2], function(err, results){
                if (err) {
                    console.error("Error inserting data:", err);
                    res.status(500).send("Error inserting data into the database");
                } 
                else {
                    res.redirect("/login");
                }
            });
        }
        catch (err) {
            console.error("Error hashing password:", err);
            res.status(500).send("Internal Server Error");
        }
    });
});

  
app.post("/loginForm", function(req, res){
    const { username, password } = req.body;
  
    const query = "SELECT * FROM user WHERE username = ?";
    db.query(query, [username], async (err, results)=>{
        if (err) {
            console.error("Error querying database:", err);
            res.status(500).send("Error fetching data from the database");
        } 
        if (results.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid username or password" });
        }
        const user = results[0];
        try{
            if (await argon2.verify(user.npassword, password)) {
                return res.json({ success: true, userName: user.username });
            } 
            else {
                res.status(401).json({ success: false, message: 'Invalid username or password' });
            }
        }
        catch (err) {
            console.error("Error verifying password:", err);
            res.status(500).send("Internal Server Error");
        }
    });
});
  
  app.post("/forgetForm", function(req, res){
    const { name, upassword, precovery } = req.body;
    const query1 = 'SELECT * FROM user WHERE username = ?';
    db.query(query1, [name], async (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).send("Internal Server Error");
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const user = results[0];

        try {
            if (precovery === user.precovery) { 
            const hashedPassword = await argon2.hash(upassword);
            const query = "UPDATE user SET npassword = ? WHERE username = ?";
            db.query(query, [hashedPassword, name], (err, results) => {
                if (err) {
                    console.error("Error updating password:", err);
                    res.status(500).send("Error updating password");
                } 
                else {
                    if (results.affectedRows > 0) {
                        res.redirect("/login");
                    }
                    else {
                        res.json({ success: false, message: "User not found" });
                    }
                }
            });
            }
        }
        catch (err) {
            console.error("Error hashing new password:", err);
            res.status(500).send("Internal Server Error");
        }
    });
});
  
  app.post("/subscription", function(req,res){
    const { firstName, lastName, dob, riotId, experience, discordId, planDetails, UserName } = req.body;
  
    const query = "Insert into subscription (firstName, lastName, dob, riotId, experience, discordId, planDetails, username) Values (?,?,?,?,?,?,?,?)";
    db.query(query,[ firstName, lastName, dob, riotId, experience, discordId, planDetails, UserName], function(err,results){
        if(err){
            console.error("Error inserting data:", err);
            res.status(500).send("Error submitting order");
        }
        else{
            res.redirect("/index");
        }
    });
});
  

app.listen(6161, () => {
    console.log("Server is running on http://localhost:6161");
});
  