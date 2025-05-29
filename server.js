// server.js (or your main server file)
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const Papa = require('papaparse');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

const ALLOWED_ORIGINS = [
    'http://localhost:5173',
    'http://kycsync.com',
    'https://kycsync.com',
    'http://www.kycsync.com',
    'https://www.kycsync.com',
    'http://kycsync.com:5173',
];

// Add Cloudflare IP handling
app.set('trust proxy', true);

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps, curl requests, or Cloudflare)
        if (!origin) return callback(null, true);
        
        if (ALLOWED_ORIGINS.indexOf(origin) === -1) {
            console.log(`Rejected origin: ${origin}`);
            return callback(null, true); // Allow all origins in production
        }
        return callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control', 'Accept', 'CF-Connecting-IP', 'CF-IPCountry', 'CF-RAY', 'CF-Visitor'],
    credentials: true,
}));

app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-super-secret-key', // Use a strong secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24, // Cookie expiration time (e.g., 24 hours)
        sameSite: 'lax', // Recommended for security
    },
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
    'https://data.opensanctions.org/datasets/latest/peps/targets.simple.csv',
    'https://data.opensanctions.org/datasets/latest/debarment/targets.simple.csv',
];

const UPDATE_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours

// --- Helper Functions ---
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

// --- Data Fetching and Population ---
async function fetchAndPopulateData() {
    try {
        for (const url of SANCTIONS_URLS) {
            const response = await fetch(url);
            if (!response.ok) {
                console.error(`Failed to fetch ${url}: ${response.status} ${response.statusText}`);
                continue;
            }

            // Get the response as text and process in chunks
            const text = await response.text();
            const chunkSize = 1024 * 1024; // 1MB chunks
            
            for (let i = 0; i < text.length; i += chunkSize) {
                const chunk = text.slice(i, i + chunkSize);
                await processDataChunk(chunk, url);
            }
        }
        console.log('Data population complete.');
    } catch (error) {
        console.error('Error in fetchAndPopulateData:', error);
    }
}

async function processDataChunk(chunk, url) {
    return new Promise((resolve, reject) => {
        Papa.parse(chunk, {
            header: true,
            skipEmptyLines: true,
            complete: async (results) => {
                try {
                    const rows = results.data;
                    // Process in smaller batches to prevent memory issues
                    const batchSize = 100;
                    for (let i = 0; i < rows.length; i += batchSize) {
                        const batch = rows.slice(i, i + batchSize);
                        await processBatch(batch, url);
                    }
                    resolve();
                } catch (error) {
                    reject(error);
                }
            },
            error: (error) => reject(error)
        });
    });
}

async function processBatch(rows, url) {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        
        for (const row of rows) {
            if (!row.name) continue;

            await connection.execute(
                'INSERT INTO persons (name, type, country, identifiers, riskLevel, sanctions, dataset, lastUpdated) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE type = VALUES(type), country = VALUES(country), identifiers = VALUES(identifiers), riskLevel = VALUES(riskLevel), sanctions = VALUES(sanctions), dataset = VALUES(dataset), lastUpdated = VALUES(lastUpdated)',
                [
                    row.name,
                    getTypeFromDataset(url),
                    row.countries || 'N/A',
                    row.identifiers || 'N/A',
                    calculateRiskLevel(url),
                    row.sanctions ? JSON.stringify([row.sanctions]) : '[]',
                    url,
                    new Date().toISOString().slice(0, 19).replace('T', ' ')
                ]
            );
        }
        
        await connection.commit();
    } catch (error) {
        await connection.rollback();
        throw error;
    } finally {
        connection.release();
    }
}

// --- Database Initialization ---
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log("✅ Connected to MySQL database!");
        connection.release();

        // Create users table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                role VARCHAR(255) NOT NULL DEFAULT 'user',
                credits INT NOT NULL DEFAULT 0
            )
        `);
        console.log("✅ Users table ready.");
        
        // Check if the credits column exists in users table
        const [creditsColumn] = await pool.execute("SHOW COLUMNS FROM users LIKE 'credits'");
        if (creditsColumn.length === 0) {
            console.log("Adding credits column to users table");
            await pool.execute("ALTER TABLE users ADD COLUMN credits INT NOT NULL DEFAULT 0");
        }
        
        // Create credit_transactions table if it doesn't exist
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS credit_transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                amount INT NOT NULL,
                transaction_type ENUM('purchase', 'usage') NOT NULL,
                description VARCHAR(255),
                payment_method VARCHAR(50),
                payment_id VARCHAR(255),
                payment_details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        console.log("✅ Credit transactions table ready.");
        
        // Create profile_credits table to track credit usage per profile
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS profile_credits (
                id INT AUTO_INCREMENT PRIMARY KEY,
                profile_name VARCHAR(255) NOT NULL,
                user_id INT NOT NULL,
                used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        console.log("✅ Profile credits table ready.");

        // Create persons table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS persons (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                type VARCHAR(255),
                country VARCHAR(255),
                identifiers TEXT,
                riskLevel INT,
                sanctions JSON,
                dataset VARCHAR(255),
                lastUpdated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("✅ Persons table ready.");
        
        // Create credit_transactions table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS credit_transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                amount INT NOT NULL,
                transaction_type ENUM('purchase', 'usage') NOT NULL,
                description VARCHAR(255),
                payment_method VARCHAR(50),
                payment_id VARCHAR(255),
                payment_details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        console.log("✅ Credit transactions table ready.");
        
        // Create profiles_credits table to track credit usage per profile
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS profile_credits (
                id INT AUTO_INCREMENT PRIMARY KEY,
                profile_name VARCHAR(255) NOT NULL,
                user_id INT NOT NULL,
                used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        console.log("✅ Profile credits table ready.");

        // Create user_tracking table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS user_tracking (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                name VARCHAR(255) NOT NULL,
                startDate DATETIME,
                stopDate DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (name) REFERENCES persons(name),
                UNIQUE KEY unique_user_person (user_id, name)
            )
        `);
        console.log("✅ User Tracking table ready.");

        // Create individualob table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS individualob (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                resident_status VARCHAR(50),
                gender VARCHAR(50),
                date_of_birth DATE,
                nationality VARCHAR(255),
                country_of_residence VARCHAR(255),
                other_nationalities TINYINT(1),
                specified_other_nationalities VARCHAR(255),
                national_id_number VARCHAR(255),
                national_id_expiry DATE,
                passport_number VARCHAR(255),
                passport_expiry DATE,
                address VARCHAR(255),
                state VARCHAR(255),
                city VARCHAR(255),
                zip_code VARCHAR(255),
                contact_number VARCHAR(255),
                dialing_code VARCHAR(255),
                work_type VARCHAR(50),
                industry VARCHAR(255),
                product_type_offered VARCHAR(255),
                product_offered VARCHAR(255),
                company_name VARCHAR(255),
                position_in_company VARCHAR(255),
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        console.log("✅ individualob table ready.");

        // Create companyob table
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS companyob (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                company_name VARCHAR(255) NOT NULL,
                registration_number VARCHAR(255),
                company_type VARCHAR(100),
                incorporation_date DATE,
                business_nature VARCHAR(255),
                industry_sector VARCHAR(255),
                annual_turnover DECIMAL(15,2),
                employee_count INT,
                website_url VARCHAR(255),
                registered_address VARCHAR(255),
                operating_address VARCHAR(255),
                country VARCHAR(100),
                state VARCHAR(100),
                city VARCHAR(100),
                postal_code VARCHAR(20),
                contact_person_name VARCHAR(255),
                contact_email VARCHAR(255) UNIQUE,
                contact_phone VARCHAR(50),
                tax_number VARCHAR(100),
                regulatory_licenses TEXT,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        console.log("✅ companyob table ready.");

        // Create edited_profiles table to store profile edit history
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS edited_profiles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                profile_id INT NOT NULL,
                original_name VARCHAR(255),
                full_name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                resident_status VARCHAR(50),
                gender VARCHAR(20),
                date_of_birth DATE,
                nationality VARCHAR(3),
                country_of_residence VARCHAR(3),
                other_nationalities BOOLEAN DEFAULT FALSE,
                specified_other_nationalities VARCHAR(3),
                national_id_number VARCHAR(100),
                national_id_expiry DATE,
                passport_number VARCHAR(100),
                passport_expiry DATE,
                address TEXT,
                state VARCHAR(100),
                city VARCHAR(100),
                zip_code VARCHAR(20),
                contact_number VARCHAR(50),
                dialing_code VARCHAR(10),
                work_type VARCHAR(50),
                industry VARCHAR(100),
                product_type_offered VARCHAR(50),
                product_offered VARCHAR(255),
                company_name VARCHAR(255),
                position_in_company VARCHAR(100),
                edited_by VARCHAR(100),
                edited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_profile_id (profile_id),
                INDEX idx_original_name (original_name),
                INDEX idx_edited_at (edited_at)
            )
        `);
        console.log("✅ edited_profiles table ready.");

        // Create trigger for profile updates
        try {
            // First drop the trigger if it exists to avoid errors
            // Use direct query execution instead of prepared statements for triggers
            const connection = await pool.getConnection();
            try {
                await connection.query("DROP TRIGGER IF EXISTS after_profile_update");
                
                // Then create the trigger
                await connection.query(`
                    CREATE TRIGGER after_profile_update
                    AFTER UPDATE ON persons
                    FOR EACH ROW
                    BEGIN
                        IF OLD.name != NEW.name OR OLD.identifiers != NEW.identifiers THEN
                            INSERT INTO edited_profiles (
                                profile_id,
                                original_name,
                                full_name,
                                email,
                                edited_by
                            )
                            VALUES (
                                NEW.id,
                                OLD.name,
                                NEW.name,
                                '',
                                USER()
                            );
                        END IF;
                    END
                `);
                console.log("✅ Profile update trigger ready.");
            } catch (error) {
                console.error("Error creating trigger:", error);
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error("Error creating trigger:", error);
        }

        // Add index to improve query performance
        try {
            // Create indexes one by one with error handling
            const createIndexQueries = [
                'CREATE INDEX idx_persons_name ON persons(name)',
                'CREATE INDEX idx_persons_identifiers ON persons(identifiers(255))',
                'CREATE INDEX idx_user_tracking_user_id ON user_tracking(user_id)',
                'CREATE INDEX idx_companyob_user_id ON companyob(user_id)',
                'CREATE INDEX idx_individualob_user_id ON individualob(user_id)'
            ];

            for (const query of createIndexQueries) {
                try {
                    await pool.execute(query);
                } catch (err) {
                    // Ignore error if index already exists
                    if (!err.message.includes('Duplicate')) {
                        console.error(`Error creating index: ${err.message}`);
                    }
                }
            }
        } catch (error) {
            console.error("Error creating indexes:", error);
            // Continue execution even if index creation fails
        }

        // Add status column to existing tables if it doesn't exist
        try {
            // Check if the status column exists in individualob
            const [indColumns] = await pool.execute("SHOW COLUMNS FROM individualob LIKE 'status'");
            if (indColumns.length === 0) {
                console.log("Adding status column to individualob table");
                await pool.execute("ALTER TABLE individualob ADD COLUMN status VARCHAR(50) DEFAULT 'pending'");
            }

            // Check if the status column exists in companyob
            const [compColumns] = await pool.execute("SHOW COLUMNS FROM companyob LIKE 'status'");
            if (compColumns.length === 0) {
                console.log("Adding status column to companyob table");
                await pool.execute("ALTER TABLE companyob ADD COLUMN status VARCHAR(50) DEFAULT 'pending'");
            }
            
            // Check if the credits column exists in users table
            const [creditsColumn] = await pool.execute("SHOW COLUMNS FROM users LIKE 'credits'");
            if (creditsColumn.length === 0) {
                console.log("Adding credits column to users table");
                await pool.execute("ALTER TABLE users ADD COLUMN credits INT NOT NULL DEFAULT 0");
            }
        } catch (error) {
            console.error("Error adding columns:", error);
            // Continue execution even if column addition fails
        }

        await fetchAndPopulateData();
        setInterval(fetchAndPopulateData, UPDATE_INTERVAL);

    } catch (error) {
        console.error("❌ Database setup error:", error);
        process.exit(1);
    }
})();

// --- Middleware for Authentication ---
const requireAuth = (req, res, next) => {
    if (!req.session.user || !req.session.user.id) {
        return res.status(401).json({ message: "Not authenticated" });
    }
    next();
};

// --- Credits System Middleware ---
// Check if user has enough credits and consume a credit when adding a profile
const checkAndConsumeCredit = async (req, res, next) => {
    if (!req.session.user || !req.session.user.id) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    // Skip credit check if turning tracking off
    if (req.body.isTracking === false) {
        return next();
    }

    // Check if this is a special refresh command
    if (req.params.name === '__refresh__') {
        return next();
    }

    // Check if profile has EVER been tracked before (even if inactive now)
    try {
        const [trackingRows] = await pool.execute(
            `SELECT * FROM user_tracking 
             WHERE user_id = ? AND name = ?`,
            [req.session.user.id, req.params.name]
        );
        
        // If the profile has been tracked before (even if currently inactive), don't charge again
        if (trackingRows.length > 0) {
            return next();
        }
    } catch (error) {
        console.error('Error checking existing tracking:', error);
        // Continue to credit check even if this fails
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        
        // Check if user has credits
        const [userRows] = await connection.execute(
            'SELECT credits FROM users WHERE id = ?',
            [req.session.user.id]
        );
        
        if (userRows.length === 0 || userRows[0].credits <= 0) {
            await connection.rollback();
            return res.status(402).json({ 
                message: 'Insufficient credits',
                needCredits: true
            });
        }
        
        // Deduct a credit only if tracking is being turned on
        if (req.body.isTracking === true) {
            await connection.execute(
                'UPDATE users SET credits = credits - 1 WHERE id = ?',
                [req.session.user.id]
            );
            
            // Record the transaction
            await connection.execute(
                'INSERT INTO credit_transactions (user_id, amount, transaction_type, description) VALUES (?, ?, ?, ?)',
                [req.session.user.id, 1, 'usage', `Started tracking for ${req.params.name}`]
            );
        }
        
        await connection.commit();
        
        // Store the profile name in the request for later use
        req.profileName = req.body.name || req.body.fullName || req.params.name || 'Unknown Profile';
        
        next();
    } catch (error) {
        await connection.rollback();
        console.error('Error checking credits:', error);
        res.status(500).json({ message: 'Server error' });
    } finally {
        connection.release();
    }
};

// Record profile credit usage after successful profile creation
const recordProfileCredit = async (req, res, next) => {
    try {
        if (req.profileName && req.session.user && req.session.user.id) {
            await pool.execute(
                'INSERT INTO profile_credits (profile_name, user_id) VALUES (?, ?)',
                [req.profileName, req.session.user.id]
            );
        }
    } catch (error) {
        console.error('Error recording profile credit:', error);
        // Continue execution even if recording fails
    }
    next();
};

// --- Authentication Routes ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name, role } = req.body;
        if (!email || !password || !name || !role) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        const [existingUser] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(409).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, name, role]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        req.session.user = { 
            id: user.id, 
            email: user.email, 
            name: user.name, 
            role: user.role,
            credits: user.credits || 0
        };
        req.session.isAuthenticated = true;  // You can use this if you need it elsewhere

        res.json({ 
            message: 'Login successful', 
            user: { 
                id: user.id, 
                email: user.email, 
                name: user.name, 
                role: user.role,
                credits: user.credits || 0 
            } 
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

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

app.get('/api/auth/user', requireAuth, async (req, res) => {
    try {
        // Fetch user with credits info
        const [userRows] = await pool.execute(
            'SELECT id, email, name, role, credits FROM users WHERE id = ?',
            [req.session.user.id]
        );
        
        if (userRows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const user = userRows[0];
        
        // Update session with latest user data including credits
        req.session.user = { 
            id: user.id, 
            email: user.email, 
            name: user.name, 
            role: user.role,
            credits: user.credits || 0
        };
        
        res.json({ user: req.session.user });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- Person Search and Retrieval Routes ---
app.get('/api/persons', requireAuth, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const userId = req.session.user.id;
        const startRow = (parseInt(page) - 1) * parseInt(limit) + 1;
        const endRow = startRow + parseInt(limit) - 1;

        // Build query with LEFT JOIN to individualob to check user association
        const baseQuery = `
            FROM persons p
            LEFT JOIN individualob io ON p.name = io.full_name
            WHERE (
                p.dataset != 'onboarded' 
                OR (p.dataset = 'onboarded' AND io.user_id = ?)
            )
        `;
        const params = [userId];

        // First get total count
        const countQuery = `SELECT COUNT(*) as total ${baseQuery}`;
        const [countResult] = await pool.execute(countQuery, params);
        const total = countResult[0].total;

        // Then get paginated results using ROW_NUMBER
        const query = `
            WITH numbered_rows AS (
                SELECT p.*, ROW_NUMBER() OVER (ORDER BY p.name) as row_num
                ${baseQuery}
            )
            SELECT * FROM numbered_rows 
            WHERE row_num >= ? AND row_num <= ?`;

        // Add pagination parameters
        params.push(startRow, endRow);
        
        const [rows] = await pool.execute(query, params);
        
        // Clean up the response data
        const cleanedRows = rows.map(row => {
            const { row_num, ...rest } = row;
            return rest;
        });

        res.json({
            data: cleanedRows,
            pagination: {
                total,
                page: parseInt(page),
                totalPages: Math.ceil(total / parseInt(limit)),
                limit: parseInt(limit)
            }
        });
    } catch (error) {
        console.error("Error fetching persons:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.get('/api/persons/search', requireAuth, async (req, res) => {
    try {
        const { searchTerm, searchId, page = 1, limit = 50 } = req.query;
        const userId = req.session.user.id;
        const startRow = (parseInt(page) - 1) * parseInt(limit) + 1;
        const endRow = startRow + parseInt(limit) - 1;
        
        // Build query with LEFT JOIN to individualob to check user association
        let baseQuery = `
            FROM persons p
            LEFT JOIN individualob io ON p.name = io.full_name
            WHERE 1=1
            AND (
                p.dataset != 'onboarded' 
                OR (p.dataset = 'onboarded' AND io.user_id = ?)
            )
        `;
        const params = [userId]; // Add userId as first parameter
        
        if (searchTerm) {
            baseQuery += ' AND p.name LIKE ?';
            params.push(`%${searchTerm}%`);
        }
        if (searchId) {
            baseQuery += ' AND p.identifiers LIKE ?';
            params.push(`%${searchId}%`);
        }

        // First get total count
        const countQuery = `SELECT COUNT(*) as total ${baseQuery}`;
        const [countResult] = await pool.execute(countQuery, params);
        const total = countResult[0].total;

        // Then get paginated results using ROW_NUMBER
        const query = `
            WITH numbered_rows AS (
                SELECT p.*, ROW_NUMBER() OVER (ORDER BY p.name) as row_num
                ${baseQuery}
            )
            SELECT * FROM numbered_rows 
            WHERE row_num >= ? AND row_num <= ?`;

        // Add pagination parameters
        params.push(startRow, endRow);

        console.log('Executing query:', query, 'with params:', params);
        
        const [rows] = await pool.execute(query, params);
        console.log('Search results:', rows.length, 'total:', total);
        
        res.json({
            data: rows.map(row => {
                const { row_num, ...rest } = row;
                return rest;
            }),
            pagination: {
                total,
                page: parseInt(page),
                totalPages: Math.ceil(total / parseInt(limit))
            }
        });

    } catch (error) {
        console.error('Error searching persons:', error);
        res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
});

// --- Tracking Routes ---
app.get('/api/tracking', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        console.log(`Fetching tracking data for user ${userId}`);
        
        const [rows] = await pool.execute(
            `SELECT ut.name,
                CASE
                    WHEN ut.stopDate IS NULL THEN 1
                    ELSE 0
                END as isTracking,
                ut.stopDate,
                ut.startDate,
                p.lastUpdated
             FROM user_tracking ut
             JOIN persons p ON ut.name = p.name
             WHERE ut.user_id = ?`,
            [userId]
        );
        
        console.log(`Found ${rows.length} tracked items for user ${userId}`);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching tracked persons:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// New endpoint that returns tracked persons with complete details
app.get('/api/tracked-persons', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        console.log(`Fetching tracked persons with details for user ${userId}`);

        // Get tracked persons with their complete details in a single query
        const [rows] = await pool.execute(
            `SELECT p.*, 
                CASE
                    WHEN ut.stopDate IS NULL THEN 1
                    ELSE 0
                END as isTracking,
                ut.stopDate,
                ut.startDate
             FROM user_tracking ut
             JOIN persons p ON ut.name = p.name
             WHERE ut.user_id = ?`,
            [userId]
        );

        console.log(`Found ${rows.length} tracked persons with details for user ${userId}`);
        
        if (rows.length === 0) {
            return res.json({ data: [] });
        }

        // Process the data to match the expected format
        const processedData = rows.map(row => {
            // Parse JSON fields if needed
            let sanctions = [];
            try {
                // Check if the sanctions field is valid before parsing
                if (row.sanctions && typeof row.sanctions === 'string' && row.sanctions.trim() !== '') {
                    // Try to fix common JSON issues before parsing
                    let sanitizedJson = row.sanctions;
                    // If it doesn't start with [ or {, wrap it in array brackets
                    if (!sanitizedJson.startsWith('[') && !sanitizedJson.startsWith('{')) {
                        sanitizedJson = `[${sanitizedJson}]`;
                    }
                    
                    try {
                        sanctions = JSON.parse(sanitizedJson);
                    } catch (innerError) {
                        // Second attempt: try to use empty array instead of warning
                        sanctions = [];
                    }
                }
            } catch (e) {
                // Just log once per session rather than spamming console
                console.warn(`Could not parse sanctions JSON for ${row.name || 'unknown'}`);
                sanctions = [];
            }

            return {
                id: row.id,
                name: row.name,
                type: row.type || 'Unknown',
                country: row.country || 'Unknown',
                identifiers: row.identifiers || 'N/A',
                riskLevel: row.riskLevel || 50,
                sanctions: sanctions,
                dataset: row.dataset || '',
                lastUpdated: row.lastUpdated,
                isTracking: row.isTracking,
                startDate: row.startDate,
                stopDate: row.stopDate
            };
        });

        res.json({ data: processedData });
    } catch (error) {
        console.error('Error fetching tracked persons with details:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

app.post('/api/tracking/:name', requireAuth, checkAndConsumeCredit, async (req, res) => {
    const userId = req.session.user.id;
    const { name } = req.params;
    const { isTracking } = req.body;

    console.log('Tracking update request:', { userId, name, isTracking }); // Debug log

    try {
        // First check if the person exists
        const [personExists] = await pool.execute(
            'SELECT id FROM persons WHERE name = ?',
            [name]
        );

        if (personExists.length === 0) {
            console.error(`Person not found: ${name}`);
            return res.status(404).json({ message: 'Person not found' });
        }

        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();

            if (isTracking) {
                // Start or resume tracking
                await connection.execute(
                    `INSERT INTO user_tracking (user_id, name, startDate) 
                     VALUES (?, ?, NOW())
                     ON DUPLICATE KEY UPDATE 
                     startDate = CASE 
                         WHEN stopDate IS NOT NULL THEN NOW() 
                         ELSE startDate 
                     END,
                     stopDate = NULL`,
                    [userId, name]
                );
            } else {
                // Stop tracking
                await connection.execute(
                    `UPDATE user_tracking 
                     SET stopDate = NOW() 
                     WHERE user_id = ? AND name = ? AND stopDate IS NULL`,
                    [userId, name]
                );
            }

            await connection.commit();

            // Fetch updated tracking status
            const [updatedTracking] = await connection.execute(
                `SELECT 
                    name,
                    CASE WHEN stopDate IS NULL THEN 1 ELSE 0 END as isTracking,
                    startDate,
                    stopDate
                 FROM user_tracking
                 WHERE user_id = ? AND name = ?`,
                [userId, name]
            );

            res.json({
                message: `Tracking ${isTracking ? 'started' : 'stopped'} for ${name}`,
                tracking: updatedTracking[0] || {
                    name,
                    isTracking: false,
                    startDate: null,
                    stopDate: null
                }
            });

        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error(`Error updating tracking for ${name}:`, error);
        res.status(500).json({ 
            message: 'Internal server error',
            error: error.message 
        });
    }
});

// --- Individual Onboarding Form Submission ---
app.post('/api/registerIndividual', requireAuth, checkAndConsumeCredit, async (req, res) => {
    try {
        const userId = req.session.user.id; // Get the logged-in user's ID from the session
        const {
            fullName,
            email,
            residentStatus,
            gender,
            dateOfBirth,
            nationality,
            countryOfResidence,
            otherNationalities,
            specifiedOtherNationalities,
            nationalIdNumber,
            nationalIdExpiry,
            passportNumber,
            passportExpiry,
            address,
            state,
            city,
            zipCode,
            contactNumber,
            dialingCode,
            workType,
            industry,
            productTypeOffered,
            productOffered,
            companyName,
            positionInCompany
        } = req.body;

        if (!fullName || !email) {
            return res.status(400).json({ message: 'Full name and email are required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Check if the email is already used by someone else
        const [emailCheck] = await pool.execute(
            'SELECT * FROM individualob WHERE email = ?',
            [email]
        );
        
        if (emailCheck.length > 0) {
            // Email already exists for another user
            await pool.execute('SET FOREIGN_KEY_CHECKS=1');
            
            return res.status(400).json({
                success: false,
                message: `Email ${email} is already in use by another profile. Please choose a different email.`
            });
        }
        
        // Crucial change: Add user_id to the query
        const insertQuery = `
            INSERT INTO individualob (
                user_id, full_name, email, resident_status, gender, date_of_birth,
                nationality, country_of_residence, other_nationalities,
                specified_other_nationalities, national_id_number, national_id_expiry,
                passport_number, passport_expiry, address, state, city, zip_code,
                contact_number, dialing_code, work_type, industry,
                product_type_offered, product_offered, company_name, position_in_company
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            userId, // Use the user ID from the session
            fullName,
            email,
            residentStatus,
            gender,
            dateOfBirth,
            nationality,
            countryOfResidence,
            otherNationalities ? 1 : 0, // Convert boolean to TINYINT(1)
            specifiedOtherNationalities,
            nationalIdNumber,
            nationalIdExpiry,
            passportNumber,
            passportExpiry,
            address,
            state,
            city,
            zipCode,
            contactNumber,
            dialingCode,
            workType,
            industry,
            productTypeOffered,
            productOffered,
            companyName,
            positionInCompany
        ];


        await pool.execute(insertQuery, values);
        res.status(201).json({ message: 'Individual registration successful' });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            // Handle duplicate email error
            return res.status(409).json({ message: 'Email already registered.' });
        }
        console.error('Error during individual registration:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- Company Registration ---
app.post('/api/registerCompany', requireAuth, checkAndConsumeCredit, async (req, res) => {
    try {
        const userId = req.session.user.id; // Get user ID from session
        const {
            companyName,
            registrationNumber,
            companyType,
            incorporationDate,
            businessNature,
            industrySector,
            annualTurnover,
            employeeCount,
            websiteUrl,
            registeredAddress,
            operatingAddress,
            country,
            state,
            city,
            postalCode,
            contactPersonName,
            contactEmail,
            contactPhone,
            taxNumber,
            regulatoryLicenses
        } = req.body;

        if (!companyName || !contactEmail) {
            return res.status(400).json({ message: 'Company name and contact email are required' });
        }
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(contactEmail)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Check if email already exists before attempting to insert
        const [existingEmails] = await pool.execute(
            'SELECT contact_email FROM companyob WHERE contact_email = ?',
            [contactEmail]
        );

        if (existingEmails.length > 0) {
            return res.status(409).json({ message: 'Contact email already registered.' });
        }

        // Crucial: Include user_id in the INSERT query
        const insertQuery = `
            INSERT INTO companyob (
                user_id, company_name, registration_number, company_type,
                incorporation_date, business_nature, industry_sector,
                annual_turnover, employee_count, website_url,
                registered_address, operating_address, country,
                state, city, postal_code, contact_person_name,
                contact_email, contact_phone, tax_number,
                regulatory_licenses
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            userId, // Use the user ID from the session
            companyName,
            registrationNumber,
            companyType,
            incorporationDate,
            businessNature,
            industrySector,
            annualTurnover,
            employeeCount,
            websiteUrl,
            registeredAddress,
            operatingAddress,
            country,
            state,
            city,
            postalCode,
            contactPersonName,
            contactEmail,
            contactPhone,
            taxNumber,
            regulatoryLicenses
        ];

        // Use try-catch specifically for the database operation
        try {
            await pool.execute(insertQuery, values);
            res.status(201).json({ message: 'Company registration successful' });
        } catch (dbError) {
            if (dbError.code === 'ER_DUP_ENTRY') {
                return res.status(409).json({ message: 'Contact email already registered.' });
            }
            throw dbError; // Re-throw to be caught by the outer catch block
        }

    } catch (error) {
        console.error('Error during company registration:', error);
        res.status(500).json({ message: 'Internal server error during company registration', details: error.message });
    }
});


// --- Get Individual Onboarding Data (for the logged-in user) ---
app.get('/api/individualob', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const [rows] = await pool.execute('SELECT * FROM individualob WHERE user_id = ?', [userId]);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching individual onboarding data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- Get Company Onboarding Data (for the logged-in user) ---
app.get('/api/companyob', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const [rows] = await pool.execute('SELECT * FROM companyob WHERE user_id = ?', [userId]);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching company onboarding data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Batch update status endpoint
app.post('/api/batchUpdateStatus', requireAuth, async (req, res) => {
    try {
        const { updates } = req.body;
        
        if (!Array.isArray(updates)) {
            return res.status(400).json({ message: 'Updates must be an array' });
        }

        // Start a transaction
        const connection = await pool.getConnection();
        await connection.beginTransaction();

        try {
            // Process all updates
            for (const update of updates) {
                const { type, name, status } = update;
                
                if (type === 'company') {
                    await connection.query(
                        'UPDATE companyob SET status = ? WHERE company_name = ?',
                        [status, name]
                    );
                } else if (type === 'individual') {
                    await connection.query(
                        'UPDATE individualob SET status = ? WHERE full_name = ?',
                        [status, name]
                    );
                }
            }

            // Commit the transaction
            await connection.commit();
            connection.release();
            
            res.json({ message: 'Batch update successful' });
        } catch (error) {
            // Rollback on error
            await connection.rollback();
            connection.release();
            throw error;
        }
    } catch (error) {
        console.error('Error in batch update:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- Name Match Check Endpoint ---
app.get('/api/check-name-match/:name', requireAuth, async (req, res) => {
    const { name } = req.params;
    
    if (!name || name.trim().length < 2) {
        return res.status(400).json({ 
            matched: false, 
            message: 'Name must be at least 2 characters long'
        });
    }
    
    console.log(`Checking name match for: "${name}"`);
    
    try {
        // First check for exact matches
        const [exactMatches] = await pool.execute(
            'SELECT * FROM persons WHERE name = ?',
            [name]
        );
        
        if (exactMatches.length > 0) {
            console.log(`Found exact match for "${name}"`);
            return res.json({ 
                matched: true, 
                matches: exactMatches,
                matchType: 'exact'
            });
        }
        
        // Check for partial matches (name contains the search term or vice versa)
        const nameParts = name.toLowerCase().split(/\s+/);
        
        // Generate SQL for matching any part of the name
        let sqlQuery = 'SELECT * FROM persons WHERE ';
        const conditions = [];
        const params = [];
        
        // Add condition for the full name as a partial match
        conditions.push('LOWER(name) LIKE ?');
        params.push(`%${name.toLowerCase()}%`);
        
        // Add conditions for individual name parts
        nameParts.forEach(part => {
            if (part.length >= 3) { // Only use parts that are at least 3 chars
                conditions.push('LOWER(name) LIKE ?');
                params.push(`%${part}%`);
            }
        });
        
        sqlQuery += conditions.join(' OR ');
        sqlQuery += ' LIMIT 10'; // Limit results to prevent performance issues
        
        const [partialMatches] = await pool.execute(sqlQuery, params);
        
        if (partialMatches.length > 0) {
            console.log(`Found ${partialMatches.length} partial matches for "${name}"`);
            return res.json({ 
                matched: true, 
                matches: partialMatches,
                matchType: 'partial'
            });
        }
        
        console.log(`No matches found for "${name}"`);
        return res.json({ matched: false });
        
    } catch (error) {
        console.error('Error checking name match:', error);
        res.status(500).json({ 
            matched: false, 
            message: 'Error checking name match',
            error: error.message
        });
    }
});

// Add caching middleware
const cache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

function cacheMiddleware(key, duration = CACHE_DURATION) {
    return (req, res, next) => {
        const cacheKey = `${key}-${req.session?.user?.id || 'anonymous'}-${JSON.stringify(req.query)}`;
        const cachedData = cache.get(cacheKey);
        
        if (cachedData && (Date.now() - cachedData.timestamp) < duration) {
            return res.json(cachedData.data);
        }
        
        res.originalJson = res.json;
        res.json = (data) => {
            cache.set(cacheKey, {
                data,
                timestamp: Date.now()
            });
            res.originalJson(data);
        };
        next();
    };
}

// Add garbage collection helper
function scheduleGC() {
    if (global.gc) {
        global.gc();
    }
}

// Schedule periodic garbage collection
setInterval(scheduleGC, 30000); // Run every 30 seconds

// --- Customer Approval/Rejection Routes ---
app.post('/api/customer/:type/:id/:action', requireAuth, async (req, res) => {
    const { type, id, action } = req.params;
    const userId = req.session.user.id;
    
    console.log(`Processing ${action} for ${type} with id ${id} by user ${userId}`);
    
    if (!['individual', 'company'].includes(type)) {
        return res.status(400).json({ message: 'Invalid customer type' });
    }
    
    if (!['approve', 'reject', 'process-complete'].includes(action)) {
        return res.status(400).json({ message: 'Invalid action' });
    }
    
    const connection = await pool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        if (action === 'process-complete') {
            // Mark the customer as processed
            const table = type === 'individual' ? 'individualob' : 'companyob';
            console.log(`Marking ${type} with id ${id} as processed`);
            
            const [result] = await connection.execute(
                `UPDATE ${table} SET status = 'processed' WHERE id = ? AND user_id = ?`, 
                [id, userId]
            );
            
            console.log('Update operation result:', result);
            
            await connection.commit();
            return res.json({ message: `${type} customer marked as processed` });
        } else if (action === 'reject') {
            // Update the customer status to rejected instead of deleting
            try {
                const table = type === 'individual' ? 'individualob' : 'companyob';
                const nameField = type === 'individual' ? 'full_name' : 'company_name';
                
                console.log(`Rejecting ${type} with id ${id} for user ${userId}`);
                
                // First get the customer name before updating
                const [customerRows] = await connection.execute(
                    `SELECT ${nameField} as name FROM ${table} WHERE id = ?`, 
                    [id]
                );
                
                if (customerRows.length === 0) {
                    await connection.rollback();
                    return res.status(404).json({ message: `${type} with ID ${id} not found` });
                }
                
                const customerName = customerRows[0].name;
                console.log(`Found customer to reject: ${customerName}`);
                
                // Update status to rejected
                const [updateResult] = await connection.execute(
                    `UPDATE ${table} SET status = 'rejected' WHERE id = ? AND user_id = ?`, 
                    [id, userId]
                );
                
                console.log('Update operation result:', updateResult);
                
                if (updateResult.affectedRows === 0) {
                    await connection.rollback();
                    return res.status(400).json({ 
                        message: `Failed to update ${type} status. No rows affected.`,
                        details: updateResult
                    });
                }
                
                // Remove from tracking if they were added
                const [trackingResult] = await connection.execute(
                    `UPDATE user_tracking SET stopDate = NOW() 
                     WHERE user_id = ? AND name = ? AND stopDate IS NULL`,
                    [userId, customerName]
                );
                
                console.log(`Tracking update result for ${customerName}:`, trackingResult);
                
                await connection.commit();
                
                return res.json({ 
                    message: `${type} customer rejected successfully`,
                    name: customerName,
                    id: id,
                    status: 'rejected'
                });
            } catch (error) {
                await connection.rollback();
                console.error(`Error rejecting ${type} with ID ${id}:`, error);
                return res.status(500).json({ 
                    message: `Server error while rejecting ${type}`,
                    error: error.message 
                });
            }
        } else if (action === 'approve') {
            // For approval, we need to get the customer name first
            const table = type === 'individual' ? 'individualob' : 'companyob';
            const nameField = type === 'individual' ? 'full_name' : 'company_name';
            
            console.log(`Looking up ${nameField} from ${table} where id = ${id}`);
            const [rows] = await connection.execute(
                `SELECT * FROM ${table} WHERE id = ?`, 
                [id]
            );
            
            console.log('Customer lookup result:', rows);
            
            if (rows.length === 0) {
                await connection.rollback();
                return res.status(404).json({ message: 'Customer not found' });
            }
            
            const customerData = rows[0];
            const customerName = type === 'individual' ? customerData.full_name : customerData.company_name;
            console.log(`Found customer name: ${customerName}`);
            
            // Check if this name exists in the persons table
            const [personExists] = await connection.execute(
                'SELECT id FROM persons WHERE name = ?',
                [customerName]
            );
            
            console.log('Person exists in sanctions check:', personExists.length > 0);
            
            // If the customer doesn't exist in the persons table, add them
            if (personExists.length === 0) {
                console.log(`Customer ${customerName} not found in persons table. Adding them...`);
                
                // Prepare data for persons table
                const countryField = type === 'individual' ? 'nationality' : 'country';
                const country = customerData[countryField] || 'Unknown';
                
                const identifiers = type === 'individual' 
                    ? `ID: ${customerData.national_id_number || 'N/A'}, Passport: ${customerData.passport_number || 'N/A'}`
                    : `Reg: ${customerData.registration_number || 'N/A'}, Tax: ${customerData.tax_number || 'N/A'}`;
                
                // Insert the customer into the persons table
                await connection.execute(
                    'INSERT INTO persons (name, type, country, identifiers, riskLevel, sanctions, dataset, lastUpdated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    [
                        customerName,
                        type === 'individual' ? 'Individual' : 'Company',
                        country,
                        identifiers,
                        30, // Default low risk level
                        '[]', // Empty sanctions array
                        'onboarded', // Mark as onboarded in dataset
                        new Date().toISOString().slice(0, 19).replace('T', ' ')
                    ]
                );
                
                console.log(`Added ${customerName} to persons table`);
            }
            
            // Check if the customer is already in tracking
            const [existingTracking] = await connection.execute(
                'SELECT * FROM user_tracking WHERE user_id = ? AND name = ?',
                [userId, customerName]
            );
            
            console.log('Current tracking status:', existingTracking.length > 0 ? 'being tracked' : 'not tracked');
            
            if (existingTracking.length === 0) {
                // Add to tracking if not already there
                console.log(`Adding ${customerName} to tracking for user ${userId}`);
                await connection.execute(
                    'INSERT INTO user_tracking (user_id, name, startDate) VALUES (?, ?, NOW())',
                    [userId, customerName]
                );
            } else {
                // Update tracking if already exists
                console.log(`Updating tracking for ${customerName}`);
                await connection.execute(
                    'UPDATE user_tracking SET stopDate = NULL, startDate = COALESCE(startDate, NOW()) WHERE user_id = ? AND name = ?',
                    [userId, customerName]
                );
            }
            
            // We keep the customer in the individualob/companyob table
            // but mark them as approved
            console.log(`Marking ${type} customer as approved`);
            await connection.execute(
                `UPDATE ${table} SET status = 'approved' WHERE id = ?`,
                [id]
            );
            
            await connection.commit();
            return res.json({ 
                message: `${type} customer approved and added to tracking`,
                name: customerName
            });
        }
    } catch (error) {
        await connection.rollback();
        console.error(`Error handling ${action} for ${type} customer:`, error);
        res.status(500).json({ message: 'Server error', error: error.message });
    } finally {
        connection.release();
    }
});

// --- Mark a person as matched (blacklisted) ---
app.post('/api/mark-matched/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { dataset = 'matched' } = req.body;
    
    try {
        console.log(`Marking person ${id} as matched/blacklisted`);
        
        // Update the dataset field in the persons table
        const [result] = await pool.execute(
            'UPDATE persons SET dataset = ? WHERE id = ?',
            [dataset, id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Person not found' });
        }
        
        console.log(`Successfully marked person ${id} as ${dataset}`);
        return res.json({ 
            message: `Person with ID ${id} has been marked as ${dataset}`,
            success: true
        });
    } catch (error) {
        console.error(`Error marking person ${id} as matched:`, error);
        return res.status(500).json({ 
            message: 'Server error while marking person as matched',
            error: error.message 
        });
    }
});

// --- Profile Routes ---
app.get('/api/profile/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        
        // First try to get data from persons table
        const [persons] = await pool.execute(
            'SELECT * FROM persons WHERE id = ?',
            [id]
        );
        
        if (persons.length === 0) {
            return res.status(404).json({ message: 'Profile not found' });
        }
        
        const person = persons[0];
        
        // Check if this person has extended profile info in individualob table
        const [individuals] = await pool.execute(
            'SELECT * FROM individualob WHERE full_name = ?',
            [person.name]
        );
        
        let profile = {
            id: person.id,
            name: person.name,
            fullName: person.name,
            identifiers: person.identifiers,
            type: person.type,
            country: person.country,
            riskLevel: person.riskLevel,
            dataset: person.dataset
        };
        
        // If found in individualob, add those fields
        if (individuals.length > 0) {
            const individual = individuals[0];
            
            // Merge individual data into profile
            profile = {
                ...profile,
                email: individual.email,
                residentStatus: individual.resident_status,
                gender: individual.gender,
                dateOfBirth: individual.date_of_birth,
                nationality: individual.nationality,
                countryOfResidence: individual.country_of_residence,
                otherNationalities: individual.other_nationalities === 1,
                specifiedOtherNationalities: individual.specified_other_nationalities,
                nationalIdNumber: individual.national_id_number || person.identifiers,
                nationalIdExpiry: individual.national_id_expiry,
                passportNumber: individual.passport_number,
                passportExpiry: individual.passport_expiry,
                address: individual.address,
                state: individual.state,
                city: individual.city,
                zipCode: individual.zip_code,
                contactNumber: individual.contact_number,
                dialingCode: individual.dialing_code,
                workType: individual.work_type,
                industry: individual.industry,
                productTypeOffered: individual.product_type_offered,
                productOffered: individual.product_offered,
                companyName: individual.company_name,
                positionInCompany: individual.position_in_company
            };
        }
        
        return res.json(profile);
    } catch (error) {
        console.error('Error fetching profile:', error);
        return res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/updateProfile/:id', requireAuth, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        const { id } = req.params;
        const userId = req.session.user.id;
        const {
            originalName,
            fullName,
            email,
            residentStatus,
            gender,
            dateOfBirth,
            nationality,
            countryOfResidence,
            otherNationalities,
            specifiedOtherNationalities,
            nationalIdNumber,
            nationalIdExpiry,
            passportNumber,
            passportExpiry,
            address,
            state,
            city,
            zipCode,
            contactNumber,
            dialingCode,
            workType,
            industry,
            productTypeOffered,
            productOffered,
            companyName,
            positionInCompany
        } = req.body;
        
        console.log(`Updating profile for ${originalName} with new name ${fullName}`);
        
        // Temporarily disable foreign key checks to allow updating the referenced row
        await connection.execute('SET FOREIGN_KEY_CHECKS=0');
        
        try {
            // Update the main persons table first
            await connection.execute(
                'UPDATE persons SET name = ?, identifiers = ?, country = ? WHERE id = ?',
                [fullName, nationalIdNumber, countryOfResidence, id]
            );
            
            // Then update the user_tracking table references if the name changed
            if (originalName !== fullName) {
                console.log(`Updating user_tracking references from ${originalName} to ${fullName}`);
                await connection.execute(
                    'UPDATE user_tracking SET name = ? WHERE name = ?',
                    [fullName, originalName]
                );
            }
            
            // Store the edit in the edited_profiles table
            await connection.execute(
                `INSERT INTO edited_profiles (
                    profile_id,
                    original_name,
                    full_name,
                    email,
                    resident_status,
                    gender,
                    date_of_birth,
                    nationality,
                    country_of_residence,
                    other_nationalities,
                    specified_other_nationalities,
                    national_id_number,
                    national_id_expiry,
                    passport_number,
                    passport_expiry,
                    address,
                    state,
                    city,
                    zip_code,
                    contact_number,
                    dialing_code,
                    work_type,
                    industry,
                    product_type_offered,
                    product_offered,
                    company_name,
                    position_in_company,
                    edited_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    id,
                    originalName,
                    fullName,
                    email,
                    residentStatus,
                    gender,
                    dateOfBirth,
                    nationality,
                    countryOfResidence,
                    otherNationalities ? 1 : 0,
                    specifiedOtherNationalities,
                    nationalIdNumber,
                    nationalIdExpiry,
                    passportNumber,
                    passportExpiry,
                    address,
                    state,
                    city,
                    zipCode,
                    contactNumber,
                    dialingCode,
                    workType,
                    industry,
                    productTypeOffered,
                    productOffered,
                    companyName,
                    positionInCompany,
                    req.session.user.name || 'system'
                ]
            );
            
            // Check if there's an entry in individualob table
            const [existingIndividuals] = await connection.execute(
                'SELECT * FROM individualob WHERE full_name = ?',
                [originalName]
            );
            
            if (existingIndividuals.length > 0) {
                // Check if the email is already used by someone else
                const [emailCheck] = await connection.execute(
                    'SELECT * FROM individualob WHERE email = ? AND full_name != ?',
                    [email, originalName]
                );
                
                if (emailCheck.length > 0) {
                    // Email already exists for another user
                    await connection.rollback();
                    // Re-enable foreign key checks
                    await connection.execute('SET FOREIGN_KEY_CHECKS=1');
                    
                    return res.status(400).json({
                        success: false,
                        message: `Email ${email} is already in use by another profile. Please choose a different email.`
                    });
                }
                
                // Update existing individualob record
                await connection.execute(
                    `UPDATE individualob SET 
                    full_name = ?,
                    email = ?,
                    resident_status = ?,
                    gender = ?,
                    date_of_birth = ?,
                    nationality = ?,
                    country_of_residence = ?,
                    other_nationalities = ?,
                    specified_other_nationalities = ?,
                    national_id_number = ?,
                    national_id_expiry = ?,
                    passport_number = ?,
                    passport_expiry = ?,
                    address = ?,
                    state = ?,
                    city = ?,
                    zip_code = ?,
                    contact_number = ?,
                    dialing_code = ?,
                    work_type = ?,
                    industry = ?,
                    product_type_offered = ?,
                    product_offered = ?,
                    company_name = ?,
                    position_in_company = ?
                    WHERE full_name = ?`,
                    [
                        fullName,
                        email,
                        residentStatus,
                        gender,
                        dateOfBirth,
                        nationality,
                        countryOfResidence,
                        otherNationalities ? 1 : 0,
                        specifiedOtherNationalities,
                        nationalIdNumber,
                        nationalIdExpiry,
                        passportNumber,
                        passportExpiry,
                        address,
                        state,
                        city,
                        zipCode,
                        contactNumber,
                        dialingCode,
                        workType,
                        industry,
                        productTypeOffered,
                        productOffered,
                        companyName,
                        positionInCompany,
                        originalName
                    ]
                );
            } else {
                // Check if the email is already used by someone else
                const [emailCheck] = await connection.execute(
                    'SELECT * FROM individualob WHERE email = ?',
                    [email]
                );
                
                if (emailCheck.length > 0) {
                    // Email already exists for another user
                    await connection.rollback();
                    // Re-enable foreign key checks
                    await connection.execute('SET FOREIGN_KEY_CHECKS=1');
                    
                    return res.status(400).json({
                        success: false,
                        message: `Email ${email} is already in use by another profile. Please choose a different email.`
                    });
                }
                
                // Insert new record in individualob table
                await connection.execute(
                    `INSERT INTO individualob (
                        user_id,
                        full_name,
                        email,
                        resident_status,
                        gender,
                        date_of_birth,
                        nationality,
                        country_of_residence,
                        other_nationalities,
                        specified_other_nationalities,
                        national_id_number,
                        national_id_expiry,
                        passport_number,
                        passport_expiry,
                        address,
                        state,
                        city,
                        zip_code,
                        contact_number,
                        dialing_code,
                        work_type,
                        industry,
                        product_type_offered,
                        product_offered,
                        company_name,
                        position_in_company,
                        status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        userId,
                        fullName,
                        email,
                        residentStatus,
                        gender,
                        dateOfBirth,
                        nationality,
                        countryOfResidence,
                        otherNationalities ? 1 : 0,
                        specifiedOtherNationalities,
                        nationalIdNumber,
                        nationalIdExpiry,
                        passportNumber,
                        passportExpiry,
                        address,
                        state,
                        city,
                        zipCode,
                        contactNumber,
                        dialingCode,
                        workType,
                        industry,
                        productTypeOffered,
                        productOffered,
                        companyName,
                        positionInCompany,
                        'approved' // Set as approved since it's coming from edit
                    ]
                );
            }
            
            await connection.commit();
            
            // Re-enable foreign key checks
            await connection.execute('SET FOREIGN_KEY_CHECKS=1');
            
            return res.json({
                success: true,
                message: 'Profile updated successfully'
            });
        } catch (error) {
            await connection.rollback();
            console.error('Error updating profile:', error);
            
            // Make sure to re-enable foreign key checks even on error
            try {
                await connection.execute('SET FOREIGN_KEY_CHECKS=1');
            } catch (fkError) {
                console.error('Error re-enabling foreign key checks:', fkError);
            }
            
            return res.status(500).json({
                success: false,
                message: 'Server error updating profile',
                error: error.message
            });
        } finally {
            // As a final safeguard, try to re-enable foreign key checks
            try {
                await connection.execute('SET FOREIGN_KEY_CHECKS=1');
            } catch (e) {
                // Just log the error, we're in finally block
                console.error('Error in finally block re-enabling foreign key checks:', e);
            }
            connection.release();
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error updating profile',
            error: error.message
        });
    }
});

// --- Credits System Endpoints ---

// Get user credits information
app.get('/api/credits', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        console.log('Fetching credits for user:', userId);
        console.log('Session user data:', req.session.user);

        // First verify the user exists and get their credits
        const [userRows] = await pool.execute(
            'SELECT id, email, name, credits FROM users WHERE id = ?',
            [userId]
        );

        if (userRows.length === 0) {
            console.log('User not found in database:', userId);
            return res.status(404).json({ message: 'User not found' });
        }

        const user = userRows[0];
        console.log('Raw user data from database:', user);
        console.log('Raw credits value:', user.credits);

        // Ensure credits is a number
        let credits = 0;
        if (user.credits !== null && user.credits !== undefined) {
            credits = parseInt(user.credits);
            if (isNaN(credits)) {
                console.log('Credits is NaN, defaulting to 0');
                credits = 0;
            }
        }
        console.log('Final parsed credits value:', credits);

        // Get recent transactions
        const [transactionRows] = await pool.execute(
            'SELECT * FROM credit_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
            [userId]
        );

        const response = { 
            credits: credits,
            recentTransactions: transactionRows
        };
        
        console.log('Final credits response:', response);
        res.json(response);
    } catch (error) {
        console.error('Error fetching user credits:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get subscription information
app.get('/api/subscription', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
        console.log('Fetching subscription for user:', userId);
        
        // In future implementations, fetch from a subscriptions table
        // For now, return a mock subscription based on user ID

        // Get user from database to check if we have subscription info
        const [userRows] = await pool.execute(
            'SELECT id, email, name, role FROM users WHERE id = ?',
            [userId]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if a subscriptions table exists - if not, create one for future use
        try {
            await pool.execute(`
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    plan_id VARCHAR(50) NOT NULL,
                    plan_name VARCHAR(100) NOT NULL,
                    price DECIMAL(10,2) NOT NULL,
                    currency VARCHAR(10) NOT NULL DEFAULT 'AED',
                    profile_limit INT NOT NULL,
                    start_date DATETIME NOT NULL,
                    end_date DATETIME NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    payment_id VARCHAR(255),
                    payment_method VARCHAR(50),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            `);
            console.log("✅ Subscriptions table ready for future use.");
        } catch (dbError) {
            console.error("Error creating subscriptions table:", dbError);
            // Continue execution - this is just preparation for future
        }

        // Check if user has a subscription in the subscriptions table
        let subscription = null;
        try {
            const [subRows] = await pool.execute(
                `SELECT * FROM subscriptions 
                 WHERE user_id = ? AND is_active = TRUE AND end_date > NOW()
                 ORDER BY end_date DESC
                 LIMIT 1`,
                [userId]
            );
            
            if (subRows.length > 0) {
                const sub = subRows[0];
                subscription = {
                    id: sub.plan_id,
                    name: sub.plan_name,
                    price: parseFloat(sub.price),
                    currency: sub.currency,
                    profileLimit: sub.profile_limit,
                    startDate: sub.start_date,
                    endDate: sub.end_date,
                    isActive: true,
                    isPopular: sub.plan_id === 'essential'
                };
            }
        } catch (error) {
            console.log('Error fetching from subscriptions table, likely does not exist yet:', error.message);
            // Continue to mock data
        }

        // No more mock subscriptions based on user ID
        // If no subscription is found, subscription remains null
        // This indicates the user hasn't purchased any plan

        res.json({
            subscription: subscription,
            availablePlans: [
                { id: 'starter', name: 'Starter', price: 200, currency: 'AED', profileLimit: 100, isPopular: false },
                { id: 'essential', name: 'Essential', price: 500, currency: 'AED', profileLimit: 250, isPopular: true },
                { id: 'business', name: 'Business', price: 1000, currency: 'AED', profileLimit: 500, isPopular: false },
                { id: 'corporate', name: 'Corporate', price: 1500, currency: 'AED', profileLimit: 750, isPopular: false }
            ]
        });

    } catch (error) {
        console.error('Error fetching subscription:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Purchase credits
app.post('/credits/purchase', requireAuth, async (req, res) => {
    const { amount, plan, paymentMethod, paymentId, paymentDetails } = req.body;
    
    if (!amount || amount <= 0) {
        return res.status(400).json({ message: 'Invalid credit amount' });
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        
        const userId = req.session.user.id;
        
        // Record payment information
        let paymentInfo = {
            method: paymentMethod || 'manual',
            id: paymentId || null,
            timestamp: new Date().toISOString(),
            details: paymentDetails ? JSON.stringify(paymentDetails) : null
        };
        
        // Add credits to user's account
        await connection.execute(
            'UPDATE users SET credits = credits + ? WHERE id = ?',
            [amount, userId]
        );
        
        // Record the transaction with payment information
        await connection.execute(
            'INSERT INTO credit_transactions (user_id, amount, transaction_type, description, payment_method, payment_id, payment_details) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [
                userId, 
                amount, 
                'purchase', 
                `Purchased ${plan || amount} credits via ${paymentMethod || 'manual payment'}`,
                paymentInfo.method,
                paymentInfo.id,
                paymentInfo.details
            ]
        );
        
        // Get updated credit balance
        const [rows] = await connection.execute(
            'SELECT credits FROM users WHERE id = ?',
            [userId]
        );
        
        await connection.commit();
        
        // Record successful payment in server logs
        console.log(`Payment successful - User ${userId} purchased ${amount} credits via ${paymentMethod || 'manual payment'}`);
        
        res.json({ 
            success: true, 
            message: 'Credits purchased successfully',
            newBalance: rows[0].credits
        });
    } catch (error) {
        await connection.rollback();
        console.error('Error purchasing credits:', error);
        res.status(500).json({ message: 'Failed to purchase credits' });
    } finally {
        connection.release();
    }
});

// Purchase subscription plan
app.post('/api/subscription/purchase', requireAuth, async (req, res) => {
    const { planId, paymentMethod, paymentId, paymentDetails } = req.body;
    
    if (!planId) {
        return res.status(400).json({ message: 'Plan ID is required' });
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        
        const userId = req.session.user.id;
        
        // Define available plans
        const availablePlans = {
            'starter': { 
                name: 'Starter', 
                price: 200, 
                currency: 'AED', 
                profileLimit: 100 
            },
            'essential': { 
                name: 'Essential', 
                price: 500, 
                currency: 'AED', 
                profileLimit: 250 
            },
            'business': { 
                name: 'Business', 
                price: 1000, 
                currency: 'AED', 
                profileLimit: 500 
            },
            'corporate': { 
                name: 'Corporate', 
                price: 1500, 
                currency: 'AED', 
                profileLimit: 750 
            }
        };
        
        // Check if the plan exists
        if (!availablePlans[planId]) {
            await connection.rollback();
            return res.status(400).json({ message: 'Invalid plan selected' });
        }
        
        const selectedPlan = availablePlans[planId];
        
        // Calculate subscription period - 1 year from now
        const startDate = new Date();
        const endDate = new Date();
        endDate.setFullYear(endDate.getFullYear() + 1);
        
        // Record payment information
        let paymentInfo = {
            method: paymentMethod || 'manual',
            id: paymentId || `sub_${Date.now()}`, // Generate an ID if not provided
            timestamp: new Date().toISOString(),
            details: paymentDetails ? JSON.stringify(paymentDetails) : null
        };
        
        // Deactivate any existing subscription
        await connection.execute(
            'UPDATE subscriptions SET is_active = FALSE WHERE user_id = ? AND is_active = TRUE',
            [userId]
        );
        
        // Add the new subscription
        await connection.execute(
            `INSERT INTO subscriptions (
                user_id, plan_id, plan_name, price, currency, profile_limit, 
                start_date, end_date, is_active, payment_id, payment_method
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?)`,
            [
                userId,
                planId,
                selectedPlan.name,
                selectedPlan.price,
                selectedPlan.currency,
                selectedPlan.profileLimit,
                startDate,
                endDate,
                paymentInfo.id,
                paymentInfo.method
            ]
        );
        
        // Record the transaction
        await connection.execute(
            'INSERT INTO credit_transactions (user_id, amount, transaction_type, description, payment_method, payment_id, payment_details) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [
                userId, 
                selectedPlan.price, 
                'subscription', 
                `Purchased ${selectedPlan.name} subscription plan for ${selectedPlan.price} ${selectedPlan.currency}`,
                paymentInfo.method,
                paymentInfo.id,
                paymentInfo.details
            ]
        );
        
        await connection.commit();
        
        // Record successful subscription in server logs
        console.log(`Subscription successful - User ${userId} purchased ${selectedPlan.name} plan via ${paymentInfo.method}`);
        
        res.json({ 
            success: true, 
            message: `Successfully subscribed to ${selectedPlan.name} plan`,
            subscription: {
                id: planId,
                name: selectedPlan.name,
                price: selectedPlan.price,
                currency: selectedPlan.currency,
                profileLimit: selectedPlan.profileLimit,
                startDate: startDate,
                endDate: endDate,
                isActive: true
            }
        });
    } catch (error) {
        await connection.rollback();
        console.error('Error purchasing subscription:', error);
        res.status(500).json({ message: 'Failed to purchase subscription plan' });
    } finally {
        connection.release();
    }
});

// --- Start Server ---
app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});