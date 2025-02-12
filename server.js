// server.js (Backend) - Modified and Corrected
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const Papa = require('papaparse');
const bcrypt = require('bcrypt'); // Import bcrypt
const session = require('express-session'); // Import express-session
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

// Enable CORS for all origins (for development; adjust in production)
app.use(cors({
    origin: 'http://localhost:5173', // Allow requests from your frontend
    credentials: true, // Important: Allow sending cookies
}));

app.use(express.json());

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key', // Use a strong secret in production
    resave: false,
    saveUninitialized: false, // Don't save uninitialized sessions (GDPR)
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true,  // Prevent client-side JS from accessing the cookie
        maxAge: 1000 * 60 * 60 * 24, // Cookie expiry (24 hours) - adjust as needed.
    }
}));

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

const SANCTIONS_URLS = [
    'https://data.opensanctions.org/datasets/latest/ae_local_terrorists/targets.simple.csv',
    'https://data.opensanctions.org/datasets/latest/un_sc_sanctions/targets.simple.csv',
    'https://data.opensanctions.org/datasets/20250205/peps/targets.simple.csv',
    'https://data.opensanctions.org/datasets/20250206/debarment/targets.simple.csv',
];

const UPDATE_INTERVAL = 24 * 60 * 60 * 1000;

// Function to fetch and populate data (reusable)
async function fetchAndPopulateData() {
    try {
        for (const url of SANCTIONS_URLS) {
            const response = await fetch(url);
            if (!response.ok) {
                console.error(`Failed to fetch ${url}: ${response.status} ${response.statusText}`);
                continue; // Move to the next URL
            }
            const text = await response.text();

            await new Promise((resolve, reject) => {
                Papa.parse(text, {
                    header: true,
                    skipEmptyLines: true,
                    complete: async (results) => {
                        try {
                            const rows = results.data;
                            for (const row of rows) {
                                if (!row.name) continue;

                                await pool.execute(
                                    'INSERT INTO persons (name, type, country, identifiers, riskLevel, sanctions, dataset, lastUpdated) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE type = VALUES(type), country = VALUES(country), identifiers = VALUES(identifiers), riskLevel = VALUES(riskLevel), sanctions = VALUES(sanctions), dataset = VALUES(dataset), lastUpdated = VALUES(lastUpdated)',
                                    [row.name, getTypeFromDataset(url), row.countries || 'N/A', row.identifiers || 'N/A', calculateRiskLevel(url), row.sanctions ? JSON.stringify([row.sanctions]) : '[]', url, new Date().toISOString()] //Use ISO string.
                                );
                            }
                            resolve();
                        } catch (parseError) {
                            reject(parseError);
                        }
                    },
                    error: (error) => {
                        reject(error);
                    }
                });
            });
        }
        console.log('Data population complete.');
    } catch (error) {
        console.error('Error in fetchAndPopulateData:', error);
    }
}

// Helper functions
function calculateRiskLevel(dataset) {
    if (dataset.includes('terrorists')) return 100;
    if (dataset.includes('sanctions')) return 85;
    if (dataset.includes('peps')) return 65;
    return 30;
}

function getTypeFromDataset(dataset) {
    if (dataset.includes('terrorists')) return 'Terrorist';
    if (dataset.includes('sanctions')) return 'Sanctioned';
    if (dataset.includes('peps')) return 'PEP';
    if (dataset.includes('debarment')) return 'Debarred';
    return 'Unknown';
}

// Initial database connection test and data population
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log("Connected to MySQL database!");
        connection.release();

        await fetchAndPopulateData();
        setInterval(fetchAndPopulateData, UPDATE_INTERVAL);

    } catch (error) {
        console.error("Error connecting to MySQL or populating data:", error);
        process.exit(1);
    }
})();

// --- User Authentication Routes ---

// Registration endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name, role } = req.body;
        if (!email || !password || !name || !role) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // Check if user already exists
        const [existingUser] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Hash password
        const [result] = await pool.execute(
            'INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, name, role]
        );

          // Create user-specific tracking table
        const userId = result.insertId;
        const trackingTableName = `user_${userId}_tracking`;
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS ${trackingTableName} (
                name VARCHAR(255) NOT NULL PRIMARY KEY,
                isTracking BOOLEAN NOT NULL,
                stopDate VARCHAR(255)
            )
        `);


        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Login endpoint (CORRECTED)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0]; // Get the first user from the result array

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' }); // User not found
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid credentials' }); // Incorrect password
        }

        // Store user information in the session
        req.session.user = { id: user.id, email: user.email, name: user.name, role: user.role }; // Correctly store user information
        req.session.isAuthenticated = true; // Mark the session as authenticated

        // Send user information in the response (excluding the password)
        res.json({ message: 'Login successful', user: { id: user.id, email: user.email, name: user.name, role: user.role } });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.json({ message: 'Logout successful' });
    });
});

// Check user session (protected route)
app.get('/api/auth/user', (req, res) => {
    if (req.session.isAuthenticated && req.session.user) {
        res.json({ user: req.session.user }); //Return user info if authenticated.
    } else {
        res.status(401).json({ message: 'Not authenticated' }); //Unauthorized
    }
});



// --- Data Retrieval Routes ---

// API endpoint for searching persons
app.get('/api/persons/search', async (req, res) => {
    try {
        const { searchTerm, searchId } = req.query;
        let query = 'SELECT * FROM persons WHERE 1=1';
        const params = [];

        if (searchTerm) {
            query += ' AND LOWER(name) LIKE LOWER(?)';
            params.push(`%${searchTerm}%`);
        }
        if (searchId) {
            query += ' AND LOWER(identifiers) LIKE LOWER(?)';
            params.push(`%${searchId}%`);
        }

        console.log("Executing query:", query, "with params:", params);
        const [rows] = await pool.execute(query, params);
        console.log("Query results:", rows);
        res.json(rows);
    } catch (error) {
        console.error('Error searching persons:', error, error.stack);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// API endpoint to get all persons
app.get('/api/persons', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT * FROM persons');
        res.json(rows);
    } catch (error) {
        console.error("Error fetching all persons:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


// --- Tracking Routes ---

// Get tracked persons for the logged-in user
app.get('/api/tracking', async (req, res) => {
    if (!req.session.user || !req.session.user.id) {
        return res.status(401).json({ message: 'Not authenticated' });
    }

    const userId = req.session.user.id;
    const trackingTableName = `user_${userId}_tracking`;

    try {
        const [rows] = await pool.execute(`SELECT * FROM ${trackingTableName}`);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching tracked persons:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Start/stop tracking a person for the logged-in user
app.post('/api/tracking/:name', async (req, res) => {
    if (!req.session.user || !req.session.user.id) {
        return res.status(401).json({ message: 'Not authenticated' });
    }

    const userId = req.session.user.id;
    const trackingTableName = `user_${userId}_tracking`;
    const { name } = req.params;
    const { isTracking, stopDate } = req.body; // Expecting { isTracking: boolean, stopDate?: string }

    try {
      if (isTracking) {
        // Start tracking (or update if already exists)
        await pool.execute(
          `INSERT INTO ${trackingTableName} (name, isTracking) VALUES (?, ?)
            ON DUPLICATE KEY UPDATE isTracking = VALUES(isTracking), stopDate = NULL`,  // Clear stopDate when starting tracking
          [name, true]
        );
      } else {
        // Stop tracking.  Crucially, *don't* delete.  Update with stopDate.
        await pool.execute(
          `UPDATE ${trackingTableName} SET isTracking = ?, stopDate = ? WHERE name = ?`,
          [false, stopDate || new Date().toISOString(), name]  // Set stopDate
        );
      }

      res.json({ message: `Tracking status updated for ${name}` });
    } catch (error) {
        console.error('Error updating tracking status:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


app.listen(port, () => {
    console.log(`Backend server listening on port ${port}`);
});