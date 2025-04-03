const express = require('express');
const bcrypt = require('bcrypt');
const app = express();
const jwt = require('jsonwebtoken');
require('dotenv').config();
app.use(express.json()); // 'Allows' the application to use json from the body passed from the requst

let users = []; // list of users


// List every user created => testing purpose
app.get('/users', AuthenticateToken, (request, response) => {

    response.json(users.filter(user => user.name === request.body.name)); // Gets only where the user name is equal to the one existing in the request

});

app.post('/users', async (request, response) => {

    try { 
        let salt = await bcrypt.genSalt(10) // per default is 10;
        let hashedPassword =  await bcrypt.hash(request.body.password, salt)  // cryptographing password.
    
        const user = {name: request.body.name, password: hashedPassword} //  'Creating' user
    
        users.push(user); // Putting into array users
        response.sendStatus(201); // 'Created' status code
    }
    catch(error) {console.log(error)}
});



// "Autenticating" the user ?
app.post('/users/login', async (request,response) => {


    let user = users.find(user => user.name === request.body.name);

    if(user == null) {
        return response.sendStatus(400)
    }

    try{ 
        // Comparing requested password with the one that is hashed. => It hashes de first password to compare to the hashed versionof it
        if (await bcrypt.compare(request.body.password, user.password)){
            response.send("logged in");

       
            // Generates the jwt token
            const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
            response.json({accessToken: accessToken})


        } else {
            response.sendStatus(401) //  not allowed
        }
    }
    catch(error) {
        response.sendStatus(500).send(); // internal server error
    }
})


function AuthenticateToken(request, response, next) {

    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // either undefined or the actual token

    if(token == null) return response.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, user) =>{

        if (error) return response.sendStatus(403) // no longer valid token

        request.user = user;

        next(); // Function that passes the control to the next middleware in the stack
    })

}

app.listen(3000, () => console.log("running..."));