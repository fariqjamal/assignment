const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const uri = "mongodb+srv://fariqjamal8:Fareq2345!@cluster0.tj0owdu.mongodb.net/";

const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Welcome to web app Secure Info',
            version: '1.0.0'
        },
        components: {  // Add 'components' section
            securitySchemes: {  // Define 'securitySchemes'
                bearerAuth: {  // Define 'bearerAuth'
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});


async function run() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  console.log("You successfully connected to MongoDB!");

  app.use(express.json());
  app.listen(port, () => {
    console.log(`Server listening at http://localSecurity:${port}`);
  });

  app.get('/', (req, res) => {
    res.send('Server Group 20 Information Security');
  });

  /**
 * @swagger
 * /registerAdmin:
 *   post:
 *     summary: Register an admin
 *     description: Register a new admin with username, password, name, email, phoneNumber, and role
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [Admin]
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *               - role
 *     responses:
 *       '200':
 *         description: Admin registered successfully
 *       '400':
 *         description: Username already registered
 */
  
  app.post('/registerAdmin', async (req, res) => {
    let data = req.body;
    res.send(await registerAdmin(client, data));
  });

  /**
 * @swagger
 * /loginAdmin:
 *   post:
 *     summary: Login as admin
 *     description: Authenticate and log in as admin with username and password, and receive a token
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the admin
 *               password:
 *                 type: string
 *                 description: The password of the admin
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Admin login successful, provides a token
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
  app.post('/loginAdmin', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });

  /**
 * @swagger
 * /loginSecurity:
 *   post:
 *     summary: Login as a security user
 *     description: Login as a security user with username and password
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the security user
 *               password:
 *                 type: string
 *                 description: The password of the security user
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Login successful
 *       '401':
 *         description: Unauthorized - Invalid username or password
 */
  app.post('/loginSecurity', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });
    
/**
 * @swagger
 * /registerSecurity:
 *   post:
 *     summary: Register a new security user
 *     description: Register a new security user with username, password, name, email, and phoneNumber
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the security
 *               password:
 *                 type: string
 *                 description: The password of the security
 *               name:
 *                 type: string
 *                 description: The name of the security
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The email of the security
 *               phoneNumber:
 *                 type: string
 *                 description: The phone number of the security
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Security user registered successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '400':
 *         description: Username already in use, please enter another username
 */

  app.post('/registerSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

/**
 * @swagger
 * /readAdmin:
 *   get:
 *     summary: Read admin data
 *     description: Retrieve admin data using a valid token obtained from loginAdmin
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Admin data retrieval successful
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with admin access
 */
  app.get('/readAdmin', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });



/**
 * @swagger
 * /registerHost:
 *   post:
 *     summary: Register a new host
 *     description: Register a new host with username, password, name, email, and phoneNumber
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the host
 *               password:
 *                 type: string
 *                 description: The password of the host
 *               name:
 *                 type: string
 *                 description: The name of the host
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The email of the host
 *               phoneNumber:
 *                 type: string
 *                 description: The phone number of the host
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Host registered successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '400':
 *         description: Username already in use, please enter another username
 */

app.post('/registerHost', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });


/**
 * @swagger
 * /loginHost:
 *   post:
 *     summary: Login as a host
 *     description: Authenticate and log in as a host with username and password, and receive a token
 *     tags:
 *       - Host
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the host
 *               password:
 *                 type: string
 *                 description: The password of the host
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Host login successful, provides a token
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */

app.post('/loginHost', async (req, res) => {
    let hostData = req.body;
    res.send(await login(client, hostData));
  });
  
  /**
 * @swagger
 * /readRecords:
 *   get:
 *     summary: Read records by Host
 *     description: Retrieve records with authorization based on the provided host token.
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Successfully retrieved records with host authorization.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *       '401':
 *         description: Unauthorized. Invalid or missing token.
 */
  app.get('/readRecords', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await readRecords(client, data));
  });


/**
 * @swagger
 * /issuePass:
 *   post:
 *     summary: Issue a visitor pass
 *     description: Issue a visitor pass by a host with visitor's name, purpose of visit, host username, and host phone number.
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               visitorName:
 *                 type: string
 *               purpose:
 *                 type: string
 *             required:
 *               - visitorName
 *               - purpose
 *     responses:
 *       '200':
 *         description: Successfully issued a visitor pass.
 *         content:
 *           application/json:
 *             schema:
 *               type:object
 *       '403':
 *         description: Unauthorized. Only hosts can issue passes.
 */
    app.post('/issuePass', verifyToken, async (req, res) => {
        let data = req.user;
        let passData = req.body;
        res.send(await issuePass(client, data, passData));
    });

/**
 * @swagger
 * /retrievePass/{passIdentifier}:
 *   get:
 *     summary: Retrieve pass details by a host
 *     description: Retrieve pass details using the provided pass identifier with host authorization.
 *     tags:
 *       - Pass Management
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The unique identifier of the pass to retrieve.
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Successfully retrieved pass details.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 passIdentifier:
 *                   type: string
 *                 visitorUsername:
 *                   type: string
 *                 passDetails:
 *                   type: string
 *                 issuedBy:
 *                   type: string
 *                 HostphoneNumber:
 *                   type: string
 *                 issueTime:
 *                   type: string
 *                   format: date-time
 *       '404':
 *         description: Pass record not found.
 */

    // Endpoint to retrieve a pass using the pass identifier by a host
app.get('/retrievePass/:passIdentifier', verifyToken, async (req, res) => {
    try {
        // Extract the passIdentifier from request parameters
        const passIdentifier = req.params.passIdentifier;
        
        // Assuming req.user contains the user data after token verification
        const userData = req.user;
        
        // Call the retrievePass function to fetch the pass details by host
        const passDetails = await retrievePass(client, userData, passIdentifier);
        
        // If pass record not found, send a 404 response
        if (passDetails === 'Pass record not found.') {
            return res.status(404).json({ error: 'Pass record not found.' });
        }
        
        // Send the pass details as the response
        res.status(200).json(passDetails);
    } catch (error) {
        // Handle errors
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



/**
 * @swagger
 * /retrieveHostContact/{passIdentifier}:
 *   get:
 *     summary: Retrieve host contact number by security
 *     description: Retrieve the contact number of the host based on the visitor's pass identifier. This is a public API available only to authenticated security personnel.
 *     tags:
 *       - Security Operations
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The unique identifier of the visitor's pass.
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Successfully retrieved host contact number.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hostContactNumber:
 *                   type: string
 *                   description: Contact number of the destination host.
 *       '401':
 *         description: Unauthorized access.
 *       '404':
 *         description: Pass record not found.
 */

app.get('/retrieveHostContact/:passIdentifier', verifySecurityToken, async (req, res) => {
    try {
        // Extract the passIdentifier from request parameters
        const passIdentifier = req.params.passIdentifier;
        
        // Call the handleRetrieveHostContact function to get the host contact number
        const hostContactNumber = await handleRetrieveHostContact(client, passIdentifier);
        
        // If host contact number is null, send a 404 response
        if (!hostContactNumber) {
            return res.status(404).json({ error: 'Pass record not found.' });
        }
        
        // Return the host contact number
        res.status(200).json({ hostContactNumber });
    } catch (error) {
        // Handle errors
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

  
}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'julpassword',           //password
  { expiresIn: '2h' });  //expires after 2 hour
}

//Function to register admin
async function registerAdmin(client, data) {
  data.password = await encryptPassword(data.password);
  
  const existingUser = await client.db("assigment").collection("Admin").findOne({ username: data.username });
  if (existingUser) {
    return 'Username already registered';
  } else {
    const result = await client.db("assigment").collection("Admin").insertOne(data);
    return 'Admin registered';
  }
}


//Function to login
async function login(client, data) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const hostCollection = client.db("assigment").collection("Host");

  // Find the admin user
  let match = await adminCollection.findOne({ username: data.username });

  if (!match) {
    // Find the security user
    match = await securityCollection.findOne({ username: data.username });
  }

  if (!match) {
    // Find the regular user
    match = await hostCollection.findOne({ username: data.username });
  }

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);

    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);
      console.log(output(match.role));
      return "\nToken for " + match.name + ": " + token;
    }
     else {
      return "Wrong password";
    }
  } else {
    return "User not found";
  }
}



//Function to encrypt password
async function encryptPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds); 
  return hash 
}


//Function to decrypt password
async function decryptPassword(password, compare) {
  const match = await bcrypt.compare(password, compare)
  return match
}


//Function to register security and visitor
async function register(client, data, mydata) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const hostCollection = client.db("assigment").collection("Host");

  const tempAdmin = await adminCollection.findOne({ username: mydata.username });
  const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  const tempUser = await hostCollection.findOne({ username: mydata.username });

  if (tempAdmin || tempSecurity || tempUser) {
    return "Username already in use, please enter another username";
  }

  if (data.role === "Admin") {
    const result = await securityCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      phoneNumber: mydata.phoneNumber,
      role: "Security",
      Host: [],
    });

    return "Security registered successfully";
  }

  if (data.role === "Security") {
    const result = await hostCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      Security: data.username,
      phoneNumber: mydata.phoneNumber,
      role: "Host",
    });

    const updateResult = await securityCollection.updateOne(
      { username: data.username },
      { $push: { Host: mydata.username } }
    );

    return "Host registered successfully";
  }
}

// Function to issue a pass to a visitor by a host
async function issuePass(client, data, passData) {
    const hostCollection = client.db('assigment').collection('Host');
  
    // Check if the user has the authority to issue passes (must be a host)
    if (data.role !== 'Host') {
      return 'You do not have the authority to issue passes.';
    }
  
    // Generate a unique pass identifier (you can use a library or a combination of data)
    const passIdentifier = generatePassIdentifier();
  
    // Store the pass details in the database or any other desired storage
    const passRecord = {
      passIdentifier: passIdentifier,
      visitorName: passData.visitorName,
      purpose: passData.purpose || '',
      issuedByHost: data.username, // Host who issued the pass
      hostPhoneNumber: data.phoneNumber, // Phone number of the host
      issueTime: new Date()
    };
  
    // Insert the pass record into the Passes collection (Assuming 'Records' is the collection name)
    await client.db('assigment').collection('Records').insertOne(passRecord);
  
    // Return a success message with the pass identifier
    return `Visitor pass issued successfully with pass identifier: ${passIdentifier}`;
}

// Function to retrieve pass details by a host
async function retrievePass(client, data, passIdentifier) {
    const hostCollection = client.db('assigment').collection('Host');

    // Search for the pass record using the unique pass identifier
    const passRecord = await client.db('assigment').collection('Records').findOne({ passIdentifier: passIdentifier });
  
    // If pass record not found, return an appropriate message
    if (!passRecord) {
      return 'Pass record not found.';
    }
  
    // Return the pass details
    return passRecord;
}




//Function to read data
async function read(client, data) {
  if (data.role == 'Admin') {
    const Admins = await client.db('assigment').collection('Admin').find({ role: 'Admin' }).next();
    const Security = await client.db('assigment').collection('Security').find({ role: 'Security' }).toArray();
    const Hosts = await client.db('assigment').collection('Host').find({ role: 'Host' }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Admins, Security, Hosts, Records };
  }

  if (data.role == 'Security') {
    const Security = await client.db('assigment').collection('Security').findOne({ username: data.username });
    if (!Security) {
      return 'User not found';
    }

    const Hosts = await client.db('assigment').collection('Host').find({ Security: data.username }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Security, Hosts, Records };
  }

  if (data.role == 'Host') {
    const Hosts = await client.db('assigment').collection('Host').toArray();
    if (!Visitor) {
      return 'User not found';
    }

    const Records = await client.db('assigment').collection('Records').toArray();

    return { Hosts, Records };
  }
}

function generatePassIdentifier() {
    // Implement your logic to generate a unique identifier
    // This can be a combination of timestamp, random numbers, or any other strategy that ensures uniqueness
  
    const timestamp = new Date().getTime(); // Get current timestamp
    const randomString = Math.random().toString(36).substring(7); // Generate a random string
  
    // Combine timestamp and random string to create a unique identifier
    const passIdentifier = `${timestamp}_${randomString}`;
  
    return passIdentifier;
}
  

async function readRecords(client, data) {
    // Check if the user has the authority to read records (must be a host)
    if (data.role !== 'Host') {
      return 'You do not have the authority to read records.';
    }
  
    // Fetch all records from the database
    const records = await client.db('assigment').collection('Records').find({}).toArray();
  
    // Return the records
    return records;
}

// Function to handle retrieval of host contact number based on passIdentifier
async function handleRetrieveHostContact(client, passIdentifier) {
    // Call the retrievePass function to fetch the pass details by security
    const passDetails = await retrievePass(client, {}, passIdentifier); // Pass an empty object since security is querying
    
    // If pass record not found, return null
    if (passDetails === 'Pass record not found.') {
        return null;
    }
    
    // Return the host contact number from passDetails
    return passDetails.HostphoneNumber;
}





//Function to output
function output(data) {
  if(data == 'Admin') {
    return "You are logged in as Admin\n1)register Security\n2)read all data"
  } else if (data == 'Security') {
    return "You are logged in as Security\n1)register Visitor\n2)read security and visitor data"
  } else if (data == 'Visitor') {
    return "You are logged in as Visitor\n1)check in\n2)check out\n3)read visitor data\n4)update profile\n5)delete account"
  }
}

//to verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'julpassword', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}