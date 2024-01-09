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
            title: 'Welcome to Mobile Legend',
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
    res.send('Server Group 21 Information Security');
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
  // Check if the user has the role of 'Security'
  if (req.user.role !== 'Security') {
    return res.status(401).send('Unauthorized - Only Security Host can register hosts.');
  }

  let hostData = req.body;
  res.send(await registerHost(client, hostData));
});


  /**
 * @swagger
 * /readSecurity:
 *   get:
 *     summary: Read security user data
 *     description: Read security user data with a valid token obtained from the loginSecurity endpoint
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Security user data retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Security user not found
 */
  app.get('/readSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

/**
 * @swagger
 * /issuePass:
 *   post:
 *     summary: Issue a Host pass
 *     description: Issue a new Host pass with a valid token obtained from the loginHost endpoint
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
 *               HostUsername:
 *                 type: string
 *                 description: The username of the Host for whom the pass is issued
 *               passDetails:
 *                 type: string
 *                 description: Additional details for the pass (optional)
 *             required:
 *               - HostUsername
 *     responses:
 *       '200':
 *         description: Host pass issued successfully, returns a unique pass identifier
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Host not found
 */
app.post('/issuePass', verifyToken, async (req, res) => {
    let securityUserToken = req.headers.authorization;

    if (!securityUserToken) {
        return res.status(401).send('Unauthorized - Security user token is missing');
    }

    // Verify the security user token
    jwt.verify(securityUserToken.split(' ')[1], 'julpassword', async function (err, decodedSecurityUser) {
        if (err) {
            console.error(err);
            return res.status(401).send('Invalid security user token');
        }

        let data = decodedSecurityUser;
        let passData = req.body;
        res.send(await issuePass(client, data, passData));
    });
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
  res.send(await loginHost(client, hostData));
});

/**
 * @swagger
 * /readHost:
 *   get:
 *     summary: Read all host data
 *     description: Retrieve all host data using a valid token obtained from loginHost
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Host data retrieval successful
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with host access
 */
app.get('/readHost', verifyToken, async (req, res) => {
  let data = req.user;
  res.send(await readHost(client, data));
});


/**
 * @swagger
 * /retrievePassHost/{passIdentifier}:
 *   get:
 *     summary: Retrieve Host pass details as a host
 *     description: Retrieve pass details for a Host using the pass identifier with a valid token obtained from loginHost
 *     tags:
 *       - Host
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The unique pass identifier
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Host pass details retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Pass not found or unauthorized to retrieve
 */
app.get('/retrievePassHost/:passIdentifier', verifyToken, async (req, res) => {
  let data = req.user;
  let passIdentifier = req.params.passIdentifier;
  res.send(await retrievePassHost(client, data, passIdentifier));
});


  
}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'riqpassword',           //password
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
  const HostCollection = client.db("assigment").collection("Host");

  // Find the admin user
  let match = await adminCollection.findOne({ username: data.username });

  if (!match) {
    // Find the security user
    match = await securityCollection.findOne({ username: data.username });
  }

  if (!match) {
    // Find the regular user
    match = await HostCollection.findOne({ username: data.username });
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

// Function to retrieve pass details as a host
async function retrievePassHost(client, data, passIdentifier) {
  if (data.role == 'Security') {
    // Implement the logic to retrieve pass details as a host
    // This might involve checking if the host has the authority to retrieve the pass details
    // You can customize this based on your specific requirements
    // For simplicity, let's assume that hosts have access to all pass details
    const passDetails = await retrievePass(client, data, passIdentifier);
    return passDetails;
  } else {
    return 'Unauthorized - Only Security Host can retrieve pass details as a host.';
  }
};


//Function to decrypt password
async function decryptPassword(password, compare) {
  const match = await bcrypt.compare(password, compare)
  return match
}


//Function to register security and Host
async function register(client, data, mydata) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const HostCollection = client.db("assigment").collection("Host");

  const tempAdmin = await adminCollection.findOne({ username: mydata.username });
  const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  const tempHost = await HostCollection.findOne({ username: mydata.username });

  if (tempAdmin || tempSecurity || tempHost) {
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
    const result = await HostCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      
      Security: data.username,
      company: mydata.company,
      vehicleNumber: mydata.vehicleNumber,
      icNumber: mydata.icNumber,
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

// Function to read host data
async function readHost(client, data) {
  if (data.role == 'Security') {
    const Host = await client.db('assigment').collection('Host').find().toArray();
    return { Host };
  } else {
    return 'Unauthorized - Only Security Host can retrieve host data.';
  }
};

// Function to register a host
async function registerHost(client, hostData) {
  const hostsCollection = client.db('assigment').collection('Host');

  // Check if the username is already in use
  const existingHost = await hostsCollection.findOne({ username: hostData.username });
  if (existingHost) {
    return 'Username already in use, please enter another username';
  }

  // Insert the host data into the Host collection
  const result = await hostsCollection.insertOne(hostData);

  return 'Host registered successfully';
}

// Function to issue a pass with the security user information
async function issuePass(client, data, passData) {
    const HostCollection = client.db('assigment').collection('Host');
    const securityCollection = client.db('assigment').collection('Security');

    // Check if the security user has the authority to issue passes
    if (data.role !== 'Host') {
        return 'You do not have the authority to issue passes.';
    }

    // Find the Host for whom the pass is issued
    const Host = await HostCollection.findOne({ username: passData.HostUsername, role: 'Host' });

    if (!Host) {
        return 'Host not found';
    }

    // Generate a unique pass identifier (you can use a library or a combination of data)
    const passIdentifier = generatePassIdentifier();

    // Store the pass details in the database or any other desired storage
    // You can create a new Passes collection for this purpose
    // For simplicity, let's assume a Passes collection with a structure like { passIdentifier, HostUsername, passDetails }
    const passRecord = {
        passIdentifier: passIdentifier,
        VisitorUsername: passData.VisitorUsername,
        passDetails: passData.passDetails || '',
        issuedBy: data.username, // Security user who issued the pass
        issueTime: new Date()
    };

    // Insert the pass record into the Passes collection
    await client.db('assigment').collection('Passes').insertOne(passRecord);

    // Update the Host's information (you might want to store pass details in the Host document)
    await HostCollection.updateOne(
        { username: passData.HostUsername },
        { $set: { passIdentifier: passIdentifier } }
    );

    return `Host pass issued successfully with pass identifier: ${passIdentifier}`;
}

// Function to login as a host
async function loginHost(client, hostData) {
  const hostsCollection = client.db('assigment').collection('Host');

  // Find the host user
  const host = await hostsCollection.findOne({ username: hostData.username });

  if (host) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(hostData.password, host.password);

    if (isPasswordMatch) {
      const token = generateToken(host);
      return "\nToken for " + host.name + ": " + token;
    } else {
      return "Wrong password";
    }
  } else {
    return "Host not found";
  }
};

// Function to retrieve pass details
async function retrievePass(client, data, passIdentifier) {
    const passesCollection = client.db('assigment').collection('Passes');
    const securityCollection = client.db('assigment').collection('Security');
  
    // Check if the security user has the authority to retrieve pass details
    if (data.role !== 'Security') {
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
      HostUsername: passRecord.HostUsername,
      passDetails: passRecord.passDetails,
      issuedBy: passRecord.issuedBy,
      issueTime: passRecord.issueTime
    };
}

//Function to read data
async function read(client, data) {
  if (data.role == 'Admin') {
    const Admins = await client.db('assigment').collection('Admin').find({ role: 'Admin' }).next();
    const Securitys = await client.db('assigment').collection('Security').find({ role: 'Security' }).toArray();
    const Hosts = await client.db('assigment').collection('Host').find({ role: 'Host' }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Admins, Securitys, Hosts, Records };
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
    const Host = await client.db('assigment').collection('Host').findOne({ username: data.username });
    if (!Host) {
      return 'User not found';
    }

    const Records = await client.db('assigment').collection('Records').find({ recordID: { $in: Host.records } }).toArray();

    return { Host, Records };
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
  


//Function to update data
async function update(client, data, mydata) {
  const HostCollection = client.db("assigment").collection("Host");

  if (mydata.password) {
    mydata.password = await encryptPassword(mydata.password);
  }

  const result = await HostCollection.updateOne(
    { username: data.username },
    { $set: mydata }
  );

  if (result.matchedCount === 0) {
    return "User not found";
  }

  return "Update Successfully";
}


//Function to delete data
async function deleteUser(client, data) {
  const HostCollection = client.db("assigment").collection("Host");
  const recordsCollection = client.db("assigment").collection("Records");
  const securityCollection = client.db("assigment").collection("Security");

  // Delete user document
  const deleteResult = await HostCollection.deleteOne({ username: data.username });
  if (deleteResult.deletedCount === 0) {
    return "User not found";
  }

  // Update Hosts array in other Host' documents
  await HostCollection.updateMany(
    { Hosts: data.username },
    { $pull: { Hosts: data.username } }
  );

  // Update Hosts array in the Security collection
  await securityCollection.updateMany(
    { Hosts: data.username },
    { $pull: { Hosts: data.username } }
  );

  return "Delete Successful\nBut the records are still in the database";
}



//Function to output
function output(data) {
  if(data == 'Admin') {
    return "You are logged in as Admin\n1)register Security\n2)read all data"
  } else if (data == 'Security') {
    return "You are logged in as Security\n1)register Host\n2)read security and Host data"
  } else if (data == 'Host') {
    return "You are logged in as Host\n1)check in\n2)check out\n3)read Host data\n4)update profile\n5)delete account"
  }
}

//to verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'riqpassword', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}


