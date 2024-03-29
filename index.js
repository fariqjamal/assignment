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
            title: 'Welcome to web app Group 20',
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
 * /VisitorPass:
 *   post:
 *     summary: Issue a visitor pass
 *     description: Issue a new visitor pass with a valid token obtained from loginHost
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
 *               visitorUsername:
 *                 type: string
 *                 description: The username of the visitor for whom the pass is issued
 *               phoneNumber:
 *                 type: string
 *                 description: Additional details for the pass (optional)
 *             required:
 *               - visitorUsername
 *     responses:
 *       '200':
 *         description: Visitor pass issued successfully, returns a unique pass identifier
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Visitor not found
 */
app.post('/VisitorPass', verifyToken, async (req, res) => {
  let data = req.user;
  let passData = req.body;
  res.send(await VisitorPass(client, data, passData));
});

/**
 * @swagger
 * /retrievePass/{passIdentifier}:
 *   get:
 *     summary: Retrieve visitor pass details
 *     description: Retrieve pass details for a visitor using the pass identifier
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The unique pass identifier
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Visitor pass details retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Pass not found or unauthorized to retrieve
 */
app.get('/retrievePass/:passIdentifier', verifyToken, async (req, res) => {
  let data = req.user;
  let passIdentifier = req.params.passIdentifier;
  res.send(await retrievePass(client, data, passIdentifier));
});

/**
 * @swagger
 * /retrieveContactNumber/{passIdentifier}:
 *   get:
 *     summary: Retrieve host name and contact from visitor pass
 *     description: Retrieve the host name and contact associated with the given visitor pass (Only accessible by authenticated security user)
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The unique pass identifier
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Host name and contact retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with security access
 *       '404':
 *         description: Pass not found or unauthorized to retrieve
 */

app.get('/retrieveContactNumber/:passIdentifier', verifyToken, async (req, res) => {
  let data = req.user;
  let passIdentifier = req.params.passIdentifier;
  res.send(await retrieveHostContact(client, data, passIdentifier));
});

/**
 * @swagger
 * /registerHostPublic:
 *   post:
 *     summary: Register a new host publicly
 *     description: Register a new host with username, password, name, email, and phoneNumber without requiring a security token for approval
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
 *         description: Host registered successfully without token approval
 *       '400':
 *         description: Username already in use, please enter another username
 */

app.post('/registerHostPublic', async (req, res) => {
  try {
      const hostData = req.body;

      // Connect to MongoDB
      await client.connect();
      const db = client.db('yourDatabaseName'); // Replace 'yourDatabaseName' with your database name
      const collection = db.collection('Hosts'); // Collection name where hosts will be stored

      // Check if the username already exists
      const existingHost = await collection.findOne({ username: hostData.username });
      if (existingHost) {
          return res.status(400).send('Username already in use, please enter another username');
      }

      // Hash the password (you can use bcrypt or any other method)
      const hashedPassword = await bcrypt.hash(hostData.password, saltRounds);

      // Insert the host details into the collection
      await collection.insertOne({
          username: hostData.username,
          password: hashedPassword,
          name: hostData.name,
          email: hostData.email,
          phoneNumber: hostData.phoneNumber
      });

      // Send a success response
      res.status(200).send('Host registered successfully ');

  } catch (error) {
      console.error('Error registering host:', error);
      res.status(500).send('Internal Server Error');
  } finally {
      // Close the MongoDB connection
      await client.close();
  }
});
/**
 * @swagger
 * /deleteUser/{username}:
 *   delete:
 *     summary: Delete a user (Security or Host) by username
 *     description: Delete a Security or Host user by their username. Only accessible by Admin.
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: Username of the user to be deleted
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: User deleted successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with admin access
 *       '404':
 *         description: User not found
 */

app.delete('/deleteUser/:username', verifyToken, async (req, res) => {
  try {
    // Check if the logged-in user is an admin
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Forbidden - Only admins can perform this action.' });
    }

    const username = req.params.username;
    const resultMessage = await deleteUser(client, username);
    
    // Handle the result message
    if (resultMessage === 'User not found.') {
      return res.status(404).json({ error: resultMessage });
    } else {
      return res.status(200).json({ message: resultMessage });
    }

  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'fariqpassword',           //password
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

// Function to issue a pass
async function VisitorPass(client, data, passData) {
  const passesCollection = client.db('assigment').collection('Passes');
  

  // Check if the security user has the authority to issue passes
  if (data.role !== 'Host') {
      return 'You do not have the authority to issue passes.';
  }

  // Generate a unique pass identifier (you can use a library or a combination of data)
  const passIdentifier = generatePassIdentifier();

  // Store the pass details in the database or any other desired storage
  // For simplicity, let's assume a Passes collection with a structure like { passIdentifier, visitorUsername, phoneNumber }
  const passRecord = {
      passIdentifier: passIdentifier,
      visitorUsername: passData.visitorUsername,
      phoneNumber: passData.phoneNumber || '',
      issuedBy: data.username, // Security user who issued the pass
      issueTime: new Date()
  };

  // Insert the pass record into the Passes collection
  await passesCollection.insertOne(passRecord);

  // Return the unique pass identifier to the client
  return `Visitor pass issued successfully with pass identifier: ${passIdentifier}`;
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

// Function to retrieve pass details
async function retrievePass(client, data, passIdentifier) {
  const passesCollection = client.db('assigment').collection('Passes');
  const securityCollection = client.db('assigment').collection('Security');

  // Check if the security user has the authority to retrieve pass details
  if (data.role !== 'Host') {
    return 'You do not have the authority to retrieve pass details.';
  }

  // Find the pass record using the pass identifier
  const passRecord = await passesCollection.findOne({ passIdentifier: passIdentifier });

  if (!passRecord) {
    return 'Pass not found or unauthorized to retrieve';
  }

  // You can customize the response format based on your needs
  return {
    passIdentifier: passRecord.passIdentifier,
    visitorUsername: passRecord.visitorUsername,
    phoneNumber: passRecord.phoneNumber,
    issuedBy: passRecord.issuedBy,
    issueTime: passRecord.issueTime
  };
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

// Function to retrieve pass details
async function retrievePass(client, data, passIdentifier) {
  const passesCollection = client.db('assigment').collection('Passes');
  const securityCollection = client.db('assigment').collection('Security');

  // Check if the security user has the authority to retrieve pass details
  if (data.role !== 'Host') {
    return { error: 'You do not have the authority to retrieve pass details.' };
  }

  // Find the pass record using the pass identifier
  const passRecord = await passesCollection.findOne({ passIdentifier: passIdentifier });

  if (!passRecord) {
    return { error: 'Pass not found or unauthorized to retrieve' };
  }

  // You can customize the response format based on your needs
  return {
    passIdentifier: passRecord.passIdentifier,
    visitorUsername: passRecord.visitorUsername,
    phoneNumber: passRecord.phoneNumber,
    issuedBy: passRecord.issuedBy,
    issueTime: passRecord.issueTime
  };
}

//Function to read data
async function read(client, data) {
  if (data.role == 'Admin') {
    const Admins = await client.db('assigment').collection('Admin').find({ role: 'Admin' }).next();
    const Security = await client.db('assigment').collection('Security').find({ role: 'Security' }).toArray();
    const Hosts = await client.db('assigment').collection('Host').find({ role: 'Host' }).toArray();
    const Passes = await client.db('assigment').collection('Passes').find().toArray();

    return { Admins, Security, Hosts, Passes };
  }

  if (data.role == 'Security') {
    const Security = await client.db('assigment').collection('Security').findOne({ username: data.username });
    if (!Security) {
      return 'User not found';
    }

    const Hosts = await client.db('assigment').collection('Host').find({ Security: data.username }).toArray();
    const Passes = await client.db('assigment').collection('Passes').find().toArray();

    return { Security, Hosts, Passes };
  }

  if (data.role == 'Host') {
    const Hosts = await client.db('assigment').collection('Host').toArray();
    if (!Visitor) {
      return 'User not found';
    }

    const Passes = await client.db('assigment').collection('Passes').toArray();

    return { Hosts, Passes };
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
    const passes = await client.db('assigment').collection('Passes').find({}).toArray();
  
    // Return the records
    return passes;
}

// Function to retrieve host name and contact from visitor pass
async function retrieveHostContact(client, data, passIdentifier) {
  // Check if the user's role is 'Security'
  if (data.role !== 'Security') {
      return 'You do not have the authority to retrieve host information.';
  }

  const passesCollection = client.db('assigment').collection('Passes');
  const hostCollection = client.db('assigment').collection('Host');

  // Find the pass record using the pass identifier
  const passRecord = await passesCollection.findOne({ passIdentifier: passIdentifier });

  if (!passRecord) {
      return 'Pass not found or unauthorized to retrieve';
  }

  // Retrieve the host information associated with the pass
  const hostInfo = await hostCollection.findOne({ username: passRecord.issuedBy });

  if (!hostInfo) {
      return 'Host information not found';
  }

  // You can customize the response format based on your needs
  return {
      hostName: hostInfo.name,
      hostContact: hostInfo.phoneNumber
  };
}

async function deleteUser(client, username) {
  const securityCollection = client.db("assigment").collection("Security");
  const hostCollection = client.db("assigment").collection("Host");

  // Check if the user exists in Security collection
  let user = await securityCollection.findOne({ username: username });
  if (user) {
    await securityCollection.deleteOne({ username: username });
    return 'Security user deleted successfully.';
  }

  // Check if the user exists in Host collection
  user = await hostCollection.findOne({ username: username });
  if (user) {
    await hostCollection.deleteOne({ username: username });
    return 'Host user deleted successfully.';
  }

  // If the user doesn't exist in Security or Host collection
  return 'User not found.';
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

// Function to encrypt password (similar to your existing encryptPassword function)
async function encryptPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds);
  return hash;
}

//to verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'fariqpassword', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}