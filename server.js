// server.js (or your main server file)
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const Papa = require('papaparse');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const fetch = require('node-fetch');
const multer = require('multer');
const path = require('path');
require('dotenv').config();
const Tesseract = require('tesseract.js');
const pdfParse = require('pdf-parse');

const app = express();
const port = process.env.PORT || 3001;

const ALLOWED_ORIGINS = [
    'http://localhost:5173',
    'http://kycsync.com',
    'http://kycsync.com:5173',
    'https://kycsync.com',
    'https://www.kycsync.com',
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (ALLOWED_ORIGINS.indexOf(origin) === -1) {
            var msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control', 'Accept'],
    credentials: true,
}));

app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-super-secret-key', // Use a strong secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production' || process.env.HTTPS === 'true', // Use secure cookies in production or when HTTPS is enabled
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

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'uploads'));
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: function (req, file, cb) {
        // Accept images and PDFs
        if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Only images and PDF files are allowed'));
        }
    }
});

// Create uploads directory if it doesn't exist
const fs = require('fs');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

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

        // Create customer_activities table for tracking all customer-related activities
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS customer_activities (
                id INT AUTO_INCREMENT PRIMARY KEY,
                customer_id INT,
                customer_name VARCHAR(255) NOT NULL,
                actor VARCHAR(255) NOT NULL,
                actor_type ENUM('admin', 'system') NOT NULL,
                action TEXT NOT NULL,
                purpose VARCHAR(255),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                legal_basis VARCHAR(255),
                retention_period VARCHAR(255) DEFAULT 'Logs retained for 7 years, auto-deleted thereafter',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_customer_id (customer_id),
                INDEX idx_customer_name (customer_name),
                INDEX idx_timestamp (timestamp)
            )
        `);
        console.log("✅ Customer activities table ready.");
        
        // Add timestamp columns to existing tables if they don't exist
        try {
            // Check if the onboarded_at column exists in individualob
            const [indOnboardedColumns] = await pool.execute("SHOW COLUMNS FROM individualob LIKE 'onboarded_at'");
            if (indOnboardedColumns.length === 0) {
                console.log("Adding timestamp columns to individualob table");
                await pool.execute("ALTER TABLE individualob ADD COLUMN onboarded_at DATETIME");
                await pool.execute("ALTER TABLE individualob ADD COLUMN onboarded_by VARCHAR(255)");
                await pool.execute("ALTER TABLE individualob ADD COLUMN approved_at DATETIME");
                await pool.execute("ALTER TABLE individualob ADD COLUMN approved_by VARCHAR(255)");
                await pool.execute("ALTER TABLE individualob ADD COLUMN rejected_at DATETIME");
                await pool.execute("ALTER TABLE individualob ADD COLUMN rejected_by VARCHAR(255)");
                await pool.execute("ALTER TABLE individualob ADD COLUMN processed_at DATETIME");
            }

            // Check if the onboarded_at column exists in companyob
            const [compOnboardedColumns] = await pool.execute("SHOW COLUMNS FROM companyob LIKE 'onboarded_at'");
            if (compOnboardedColumns.length === 0) {
                console.log("Adding timestamp columns to companyob table");
                await pool.execute("ALTER TABLE companyob ADD COLUMN onboarded_at DATETIME");
                await pool.execute("ALTER TABLE companyob ADD COLUMN onboarded_by VARCHAR(255)");
                await pool.execute("ALTER TABLE companyob ADD COLUMN approved_at DATETIME");
                await pool.execute("ALTER TABLE companyob ADD COLUMN approved_by VARCHAR(255)");
                await pool.execute("ALTER TABLE companyob ADD COLUMN rejected_at DATETIME");
                await pool.execute("ALTER TABLE companyob ADD COLUMN rejected_by VARCHAR(255)");
                await pool.execute("ALTER TABLE companyob ADD COLUMN processed_at DATETIME");
            }
        } catch (error) {
            console.error("Error adding timestamp columns:", error);
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
        
        // Add onboarded_at timestamp
        const onboardedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
        
        // Crucial change: Add user_id to the query
        const insertQuery = `
            INSERT INTO individualob (
                user_id, full_name, email, resident_status, gender, date_of_birth,
                nationality, country_of_residence, other_nationalities,
                specified_other_nationalities, national_id_number, national_id_expiry,
                passport_number, passport_expiry, address, state, city, zip_code,
                contact_number, dialing_code, work_type, industry,
                product_type_offered, product_offered, company_name, position_in_company,
                onboarded_at, onboarded_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            positionInCompany,
            onboardedAt,
            req.session.user.name || 'System'
        ];


        await pool.execute(insertQuery, values);
        
        // Record the onboarding activity
        try {
            await pool.execute(
                `INSERT INTO customer_activities (
                    customer_id, 
                    customer_name, 
                    actor, 
                    actor_type, 
                    action, 
                    purpose, 
                    timestamp, 
                    legal_basis
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    null, // Will be updated once we get the customer ID
                    fullName,
                    req.session.user.name || 'System',
                    'admin',
                    'Registered new customer into the system.',
                    'Customer Onboarding',
                    onboardedAt,
                    'Legitimate interest'
                ]
            );
        } catch (activityError) {
            console.error('Error recording onboarding activity:', activityError);
            // Continue even if activity recording fails
        }
        
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

        // Add onboarded_at timestamp
        const onboardedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
        
        // Crucial: Include user_id in the INSERT query
        const insertQuery = `
            INSERT INTO companyob (
                user_id, company_name, registration_number, company_type,
                incorporation_date, business_nature, industry_sector,
                annual_turnover, employee_count, website_url,
                registered_address, operating_address, country, state,
                city, postal_code, contact_person_name, contact_email, contact_phone,
                tax_number, regulatory_licenses, onboarded_at, onboarded_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            regulatoryLicenses,
            onboardedAt,
            req.session.user.name || 'System'
        ];

        // Use try-catch specifically for the database operation
        try {
            const [result] = await pool.execute(insertQuery, values);
            
            // Record the onboarding activity
            try {
                await pool.execute(
                    `INSERT INTO customer_activities (
                        customer_id, 
                        customer_name, 
                        actor, 
                        actor_type, 
                        action, 
                        purpose, 
                        timestamp, 
                        legal_basis
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        result.insertId,
                        companyName,
                        req.session.user.name || 'System',
                        'admin',
                        'Registered new company into the system.',
                        'Customer Onboarding',
                        onboardedAt,
                        'Legitimate interest'
                    ]
                );
            } catch (activityError) {
                console.error('Error recording company onboarding activity:', activityError);
                // Continue even if activity recording fails
            }
            
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
            
            const processedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
            
            const [result] = await connection.execute(
                `UPDATE ${table} SET status = 'processed', processed_at = ? WHERE id = ? AND user_id = ?`, 
                [processedAt, id, userId]
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
                
                // Add rejected timestamp
                const rejectedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
                
                // Update status to rejected with timestamp
                const [updateResult] = await connection.execute(
                    `UPDATE ${table} SET status = 'rejected', rejected_at = ?, rejected_by = ? WHERE id = ? AND user_id = ?`, 
                    [rejectedAt, req.session.user.name || 'System', id, userId]
                );
                
                console.log('Update operation result:', updateResult);
                
                if (updateResult.affectedRows === 0) {
                    await connection.rollback();
                    return res.status(400).json({ 
                        message: `Failed to update ${type} status. No rows affected.`,
                        details: updateResult
                    });
                }
                
                // Record the rejection activity
                try {
                    await connection.execute(
                        `INSERT INTO customer_activities (
                            customer_id, 
                            customer_name, 
                            actor, 
                            actor_type, 
                            action, 
                            purpose, 
                            timestamp, 
                            legal_basis
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                        [
                            id,
                            customerName,
                            req.session.user.name || 'System',
                            'admin',
                            `${type === 'individual' ? 'Customer' : 'Company'} profile rejected.`,
                            'Account management',
                            rejectedAt,
                            'Legitimate interest'
                        ]
                    );
                } catch (activityError) {
                    console.error('Error recording rejection activity:', activityError);
                    // Continue even if activity recording fails
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
                    status: 'rejected',
                    rejected_at: rejectedAt
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
            
            // Add approved timestamp
            const approvedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
            
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
            // but mark them as approved with timestamp
            console.log(`Marking ${type} customer as approved`);
            await connection.execute(
                `UPDATE ${table} SET status = 'approved', approved_at = ?, approved_by = ? WHERE id = ?`,
                [approvedAt, req.session.user.name || 'System', id]
            );
            
            // Record the approval activity
            try {
                await connection.execute(
                    `INSERT INTO customer_activities (
                        customer_id, 
                        customer_name, 
                        actor, 
                        actor_type, 
                        action, 
                        purpose, 
                        timestamp, 
                        legal_basis
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        id,
                        customerName,
                        req.session.user.name || 'System',
                        'admin',
                        `${type === 'individual' ? 'Customer' : 'Company'} profile approved.`,
                        'Account management',
                        approvedAt,
                        'Legitimate interest'
                    ]
                );
            } catch (activityError) {
                console.error('Error recording approval activity:', activityError);
                // Continue even if activity recording fails
            }
            
            await connection.commit();
            return res.json({ 
                message: `${type} customer approved and added to tracking`,
                name: customerName,
                approved_at: approvedAt
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
                positionInCompany: individual.position_in_company,
                status: individual.status,
                onboardedAt: individual.onboarded_at,
                onboardedBy: individual.onboarded_by,
                approvedAt: individual.approved_at,
                approvedBy: individual.approved_by,
                rejectedAt: individual.rejected_at,
                rejectedBy: individual.rejected_by
            };
            
            // Fetch activities for this customer
            try {
                const [activities] = await pool.execute(
                    `SELECT * FROM customer_activities 
                     WHERE customer_name = ? 
                     ORDER BY timestamp DESC`,
                    [profile.fullName]
                );
                
                if (activities && activities.length > 0) {
                    profile.activities = activities;
                }
            } catch (activityError) {
                console.error('Error fetching customer activities:', activityError);
                // Continue without activities if there's an error
            }
        }
        
        return res.json(profile);
    } catch (error) {
        console.error('Error fetching profile:', error);
        return res.status(500).json({ message: 'Server error' });
    }
});

// New endpoint to get customer activities
app.get('/api/customer/:id/activities', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        
        // First get the customer name from either individualob or companyob
        let customerName;
        
        // Try individualob first
        const [individualResult] = await pool.execute(
            'SELECT full_name FROM individualob WHERE id = ?',
            [id]
        );
        
        if (individualResult.length > 0) {
            customerName = individualResult[0].full_name;
        } else {
            // Try companyob if not found in individualob
            const [companyResult] = await pool.execute(
                'SELECT company_name FROM companyob WHERE id = ?',
                [id]
            );
            
            if (companyResult.length > 0) {
                customerName = companyResult[0].company_name;
            } else {
                return res.status(404).json({ message: 'Customer not found' });
            }
        }
        
        // Fetch activities for this customer
        const [activities] = await pool.execute(
            `SELECT * FROM customer_activities 
             WHERE customer_name = ? 
             ORDER BY timestamp DESC`,
            [customerName]
        );
        
        // If no activities found in the dedicated table, try to create some from timestamps
        if (activities.length === 0) {
            const generatedActivities = [];
            
            // Check individualob for timestamps
            const [individualData] = await pool.execute(
                'SELECT * FROM individualob WHERE id = ? OR full_name = ?',
                [id, customerName]
            );
            
            if (individualData.length > 0) {
                const individual = individualData[0];
                
                // Add onboarding activity if timestamp exists
                if (individual.onboarded_at) {
                    generatedActivities.push({
                        id: 'onboarding',
                        customer_id: individual.id,
                        customer_name: individual.full_name,
                        actor: individual.onboarded_by || 'System',
                        actor_type: individual.onboarded_by ? 'admin' : 'system',
                        action: 'Registered new customer into the system.',
                        purpose: 'Customer Onboarding',
                        timestamp: individual.onboarded_at,
                        legal_basis: 'Legitimate interest',
                        retention_period: 'Logs retained for 7 years, auto-deleted thereafter'
                    });
                }
                
                // Add approval activity if timestamp exists
                if (individual.approved_at) {
                    generatedActivities.push({
                        id: 'approval',
                        customer_id: individual.id,
                        customer_name: individual.full_name,
                        actor: individual.approved_by || 'System',
                        actor_type: individual.approved_by ? 'admin' : 'system',
                        action: 'Customer profile approved.',
                        purpose: 'Account management',
                        timestamp: individual.approved_at,
                        legal_basis: 'Legitimate interest',
                        retention_period: 'Logs retained for 7 years, auto-deleted thereafter'
                    });
                }
                
                // Add rejection activity if timestamp exists
                if (individual.rejected_at) {
                    generatedActivities.push({
                        id: 'rejection',
                        customer_id: individual.id,
                        customer_name: individual.full_name,
                        actor: individual.rejected_by || 'System',
                        actor_type: individual.rejected_by ? 'admin' : 'system',
                        action: 'Customer profile rejected.',
                        purpose: 'Account management',
                        timestamp: individual.rejected_at,
                        legal_basis: 'Legitimate interest',
                        retention_period: 'Logs retained for 7 years, auto-deleted thereafter'
                    });
                }
                
                return res.json(generatedActivities);
            }
            
            // Check companyob for timestamps if no individual found
            const [companyData] = await pool.execute(
                'SELECT * FROM companyob WHERE id = ? OR company_name = ?',
                [id, customerName]
            );
            
            if (companyData.length > 0) {
                const company = companyData[0];
                
                // Add onboarding activity if timestamp exists
                if (company.onboarded_at) {
                    generatedActivities.push({
                        id: 'onboarding',
                        customer_id: company.id,
                        customer_name: company.company_name,
                        actor: company.onboarded_by || 'System',
                        actor_type: company.onboarded_by ? 'admin' : 'system',
                        action: 'Registered new company into the system.',
                        purpose: 'Customer Onboarding',
                        timestamp: company.onboarded_at,
                        legal_basis: 'Legitimate interest',
                        retention_period: 'Logs retained for 7 years, auto-deleted thereafter'
                    });
                }
                
                // Add approval activity if timestamp exists
                if (company.approved_at) {
                    generatedActivities.push({
                        id: 'approval',
                        customer_id: company.id,
                        customer_name: company.company_name,
                        actor: company.approved_by || 'System',
                        actor_type: company.approved_by ? 'admin' : 'system',
                        action: 'Company profile approved.',
                        purpose: 'Account management',
                        timestamp: company.approved_at,
                        legal_basis: 'Legitimate interest',
                        retention_period: 'Logs retained for 7 years, auto-deleted thereafter'
                    });
                }
                
                // Add rejection activity if timestamp exists
                if (company.rejected_at) {
                    generatedActivities.push({
                        id: 'rejection',
                        customer_id: company.id,
                        customer_name: company.company_name,
                        actor: company.rejected_by || 'System',
                        actor_type: company.rejected_by ? 'admin' : 'system',
                        action: 'Company profile rejected.',
                        purpose: 'Account management',
                        timestamp: company.rejected_at,
                        legal_basis: 'Legitimate interest',
                        retention_period: 'Logs retained for 7 years, auto-deleted thereafter'
                    });
                }
                
                return res.json(generatedActivities);
            }
            
            // If no activities could be generated
            return res.json([]);
        }
        
        return res.json(activities);
    } catch (error) {
        console.error('Error fetching customer activities:', error);
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

// --- Document Analysis Endpoints ---

// Get available OCR languages
app.get('/api/ocr-languages', requireAuth, (req, res) => {
    try {
        // Get all available languages from the language config function
        const languages = Object.entries(getLanguageConfig()).map(([code, config]) => ({
            code,
            name: config.name
        }));
        
        res.json({ languages });
    } catch (error) {
        console.error('Error fetching OCR languages:', error);
        res.status(500).json({ message: 'Error fetching OCR languages' });
    }
});

app.post('/api/analyze-document', requireAuth, upload.single('document'), async (req, res) => {
    try {
        // Check if file was uploaded
        if (!req.file) {
            return res.status(400).json({ message: 'No document uploaded' });
        }

        const documentType = req.body.documentType || 'image';
        const filePath = req.file.path;
        // Get language preference from request, default to English
        const language = req.body.language || 'eng';
        // Check if auto-detection is requested
        const autoDetectLanguage = req.body.autoDetectLanguage === 'true' || req.body.autoDetectLanguage === true;
        
        console.log(`Processing ${documentType} document: ${req.file.originalname} with language: ${autoDetectLanguage ? 'auto-detect' : language}`);
        
        let extractedText = '';
        let extractedData = {};
        let detectedLanguage = null;
        
        try {
            // Process based on file type
            if (documentType === 'pdf') {
                // Extract text from PDF
                const dataBuffer = fs.readFileSync(filePath);
                const pdfData = await pdfParse(dataBuffer);
                extractedText = pdfData.text;
                
                console.log("PDF text extracted successfully");
                
                // Try to detect language from extracted text if auto-detect is enabled
                if (autoDetectLanguage && extractedText) {
                    detectedLanguage = await detectTextLanguage(extractedText);
                    console.log(`Auto-detected language from PDF: ${detectedLanguage}`);
                }
            } else {
                // Preprocess image before OCR to improve accuracy
                const preprocessedImagePath = await preprocessImage(filePath);
                
                // If auto-detect is enabled, first run OCR with osd only to detect script/language
                if (autoDetectLanguage) {
                    try {
                        console.log("Auto-detecting language from image...");
                        const osdConfig = {
                            tessedit_ocr_engine_mode: '0', // OSD only mode
                            logger: m => console.log(m)
                        };
                        
                        const osdResult = await Tesseract.recognize(
                            preprocessedImagePath || filePath,
                            'osd', // OSD language pack
                            osdConfig
                        );
                        
                        // Extract the detected script info
                        if (osdResult.data && osdResult.data.osd) {
                            const scriptInfo = osdResult.data.osd;
                            console.log("Script detection result:", scriptInfo);
                            
                            // Map detected script to language code
                            detectedLanguage = mapScriptToLanguage(scriptInfo.script);
                            console.log(`Detected script: ${scriptInfo.script}, mapped to language: ${detectedLanguage}`);
                        }
                    } catch (osdError) {
                        console.warn("Language auto-detection failed:", osdError.message);
                        console.log("Falling back to specified language:", language);
                        detectedLanguage = language;
                    }
                }
                
                // Get language configuration for OCR - use detected language if available
                const langConfig = getLanguageConfig(detectedLanguage || language);
                
                // Define Tesseract configuration for improved accuracy
                const config = {
                    lang: langConfig.tesseractCode,
                    // Set DPI to optimal value for OCR
                    tessedit_char_whitelist: langConfig.charWhitelist,
                    // Improve image processing
                    tessjs_create_hocr: '0',
                    tessjs_create_tsv: '0',
                    // Set PSM mode to automatic page segmentation with OSD
                    tessjs_create_box: '0',
                    tessjs_create_unlv: '0',
                    tessjs_create_osd: '0',
                    tessedit_pageseg_mode: '1',
                    tessedit_ocr_engine_mode: '2', // Use LSTM neural network only
                    preserve_interword_spaces: '1',
                    user_defined_dpi: '300',
                    textord_tabfind_find_tables: '1',
                    logger: m => console.log(m) // log progress
                };
                
                console.log(`Starting OCR with enhanced configuration for language: ${langConfig.name}...`);
                
                // Use OCR for images with improved configuration
                const result = await Tesseract.recognize(
                    preprocessedImagePath || filePath,
                    langConfig.tesseractCode, // language code
                    config
                );
                
                extractedText = result.data.text;
                
                // Apply post-processing to improve text quality
                extractedText = postprocessOcrText(extractedText, langConfig.language);
                
                console.log("Image OCR completed successfully with enhanced accuracy");
            }
            
            // Parse the extracted text to find common patterns
            extractedData = parseIndividualDocumentText(extractedText);
            
            console.log("Data extraction completed:", extractedData);
            
            // Add language detection info to response
            res.json({
                ...extractedData,
                detectedLanguage: detectedLanguage || language
            });
        } catch (processingError) {
            console.error('Error processing document:', processingError);
            res.status(500).json({ message: 'Error analyzing document', error: processingError.message });
        }
    } catch (error) {
        console.error('Document analysis error:', error);
        res.status(500).json({ message: 'Error analyzing document' });
    }
});

app.post('/api/analyze-company-document', requireAuth, upload.single('document'), async (req, res) => {
    try {
        // Check if file was uploaded
        if (!req.file) {
            return res.status(400).json({ message: 'No document uploaded' });
        }

        const documentType = req.body.documentType || 'image';
        const filePath = req.file.path;
        // Get language preference from request, default to English
        const language = req.body.language || 'eng';
        // Check if auto-detection is requested
        const autoDetectLanguage = req.body.autoDetectLanguage === 'true' || req.body.autoDetectLanguage === true;
        
        console.log(`Processing company ${documentType} document: ${req.file.originalname} with language: ${autoDetectLanguage ? 'auto-detect' : language}`);
        
        let extractedText = '';
        let extractedData = {};
        let detectedLanguage = null;
        
        try {
            // Process based on file type
            if (documentType === 'pdf') {
                // Extract text from PDF
                const dataBuffer = fs.readFileSync(filePath);
                const pdfData = await pdfParse(dataBuffer);
                extractedText = pdfData.text;
                
                console.log("PDF text extracted successfully");
                
                // Try to detect language from extracted text if auto-detect is enabled
                if (autoDetectLanguage && extractedText) {
                    detectedLanguage = await detectTextLanguage(extractedText);
                    console.log(`Auto-detected language from PDF: ${detectedLanguage}`);
                }
            } else {
                // Preprocess image before OCR to improve accuracy
                const preprocessedImagePath = await preprocessImage(filePath);
                
                // If auto-detect is enabled, first run OCR with osd only to detect script/language
                if (autoDetectLanguage) {
                    try {
                        console.log("Auto-detecting language from image...");
                        const osdConfig = {
                            tessedit_ocr_engine_mode: '0', // OSD only mode
                            logger: m => console.log(m)
                        };
                        
                        const osdResult = await Tesseract.recognize(
                            preprocessedImagePath || filePath,
                            'osd', // OSD language pack
                            osdConfig
                        );
                        
                        // Extract the detected script info
                        if (osdResult.data && osdResult.data.osd) {
                            const scriptInfo = osdResult.data.osd;
                            console.log("Script detection result:", scriptInfo);
                            
                            // Map detected script to language code
                            detectedLanguage = mapScriptToLanguage(scriptInfo.script);
                            console.log(`Detected script: ${scriptInfo.script}, mapped to language: ${detectedLanguage}`);
                        }
                    } catch (osdError) {
                        console.warn("Language auto-detection failed:", osdError.message);
                        console.log("Falling back to specified language:", language);
                        detectedLanguage = language;
                    }
                }
                
                // Get language configuration for OCR - use detected language if available
                const langConfig = getLanguageConfig(detectedLanguage || language);
                
                // Define Tesseract configuration for improved accuracy
                const config = {
                    lang: langConfig.tesseractCode,
                    // Set DPI to optimal value for OCR
                    tessedit_char_whitelist: langConfig.charWhitelist,
                    // Improve image processing
                    tessjs_create_hocr: '0',
                    tessjs_create_tsv: '0',
                    // Set PSM mode to automatic page segmentation with OSD
                    tessjs_create_box: '0',
                    tessjs_create_unlv: '0',
                    tessjs_create_osd: '0',
                    tessedit_pageseg_mode: '1',
                    tessedit_ocr_engine_mode: '2', // Use LSTM neural network only
                    preserve_interword_spaces: '1',
                    user_defined_dpi: '300',
                    textord_tabfind_find_tables: '1',
                    logger: m => console.log(m) // log progress
                };
                
                console.log(`Starting OCR with enhanced configuration for language: ${langConfig.name}...`);
                
                // Use OCR for images with improved configuration
                const result = await Tesseract.recognize(
                    preprocessedImagePath || filePath,
                    langConfig.tesseractCode, // language code
                    config
                );
                
                extractedText = result.data.text;
                
                // Apply post-processing to improve text quality
                extractedText = postprocessOcrText(extractedText, langConfig.language);
                
                console.log("Image OCR completed successfully with enhanced accuracy");
            }
            
            // Parse the extracted text to find common patterns
            extractedData = parseCompanyDocumentText(extractedText);
            
            console.log("Data extraction completed:", extractedData);
            
            // Add language detection info to response
            res.json({
                ...extractedData,
                detectedLanguage: detectedLanguage || language
            });
        } catch (processingError) {
            console.error('Error processing document:', processingError);
            res.status(500).json({ message: 'Error analyzing document', error: processingError.message });
        }
    } catch (error) {
        console.error('Company document analysis error:', error);
        res.status(500).json({ message: 'Error analyzing document' });
    }
});

// Function to get language configuration for OCR
function getLanguageConfig(langCode) {
    // Default whitelist for Latin-based languages
    const defaultWhitelist = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.,;:-_()[]{}\'"/\\@#$%&*+<>!?= ';
    
    // Language configurations
    const languages = {
        'eng': {
            name: 'English',
            tesseractCode: 'eng',
            language: 'english',
            charWhitelist: defaultWhitelist
        },
        'ara': {
            name: 'Arabic',
            tesseractCode: 'ara',
            language: 'arabic',
            charWhitelist: defaultWhitelist + 'ابتثجحخدذرزسشصضطظعغفقكلمنهويءآأؤإئ'
        },
        'chi_sim': {
            name: 'Chinese (Simplified)',
            tesseractCode: 'chi_sim',
            language: 'chinese',
            charWhitelist: defaultWhitelist
        },
        'chi_tra': {
            name: 'Chinese (Traditional)',
            tesseractCode: 'chi_tra',
            language: 'chinese',
            charWhitelist: defaultWhitelist
        },
        'fra': {
            name: 'French',
            tesseractCode: 'fra',
            language: 'french',
            charWhitelist: defaultWhitelist + 'àâäæçéèêëîïôœùûüÿÀÂÄÆÇÉÈÊËÎÏÔŒÙÛÜŸ'
        },
        'deu': {
            name: 'German',
            tesseractCode: 'deu',
            language: 'german',
            charWhitelist: defaultWhitelist + 'äöüßÄÖÜ'
        },
        'hin': {
            name: 'Hindi',
            tesseractCode: 'hin',
            language: 'hindi',
            charWhitelist: defaultWhitelist
        },
        'ita': {
            name: 'Italian',
            tesseractCode: 'ita',
            language: 'italian',
            charWhitelist: defaultWhitelist + 'àèéìíîòóùúÀÈÉÌÍÎÒÓÙÚ'
        },
        'jpn': {
            name: 'Japanese',
            tesseractCode: 'jpn',
            language: 'japanese',
            charWhitelist: defaultWhitelist
        },
        'kor': {
            name: 'Korean',
            tesseractCode: 'kor',
            language: 'korean',
            charWhitelist: defaultWhitelist
        },
        'rus': {
            name: 'Russian',
            tesseractCode: 'rus',
            language: 'russian',
            charWhitelist: defaultWhitelist + 'абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'
        },
        'spa': {
            name: 'Spanish',
            tesseractCode: 'spa',
            language: 'spanish',
            charWhitelist: defaultWhitelist + 'áéíóúüñÁÉÍÓÚÜÑ¿¡'
        },
        'urd': {
            name: 'Urdu',
            tesseractCode: 'urd',
            language: 'urdu',
            charWhitelist: defaultWhitelist
        }
    };
    
    // If no language code is provided, return the entire language configuration object
    if (!langCode) {
        return languages;
    }
    
    // Return the requested language config or default to English
    return languages[langCode] || languages['eng'];
}

// Image preprocessing function to improve OCR accuracy
async function preprocessImage(inputPath) {
    try {
        // Require image processing libraries
        const { promisify } = require('util');
        const exec = promisify(require('child_process').exec);
        const path = require('path');
        
        // Create output path with _processed suffix
        const outputPath = inputPath.replace(/(\.[^.]+)$/, '_processed$1');
        
        console.log(`Preprocessing image: ${inputPath} -> ${outputPath}`);
        
        // Use ImageMagick for preprocessing if available
        try {
            // Check if ImageMagick is installed
            await exec('convert -version');
            
            // Apply a series of image processing operations to improve OCR accuracy:
            // 1. Convert to grayscale
            // 2. Add border (helps with edge detection)
            // 3. Increase contrast
            // 4. Remove noise
            // 5. Deskew (straighten) the image
            // 6. Set to 300 DPI (optimal for OCR)
            const command = `convert "${inputPath}" -colorspace gray -bordercolor White -border 10x10 -contrast-stretch 2%x98% -level 20%,80%,1 -deskew 40% -density 300 -sharpen 0x1 "${outputPath}"`;
            
            await exec(command);
            console.log('Image preprocessing completed successfully');
            return outputPath;
        } catch (error) {
            console.warn('ImageMagick not available or preprocessing failed:', error.message);
            console.log('Falling back to original image');
            return inputPath;
        }
    } catch (error) {
        console.error('Error during image preprocessing:', error);
        return inputPath; // Return original path if preprocessing fails
    }
}

// Post-processing function to clean up common OCR errors
function postprocessOcrText(text, language = 'english') {
    if (!text) return '';
    
    // Common OCR error corrections
    let processedText = text
        // Fix common character confusions
        .replace(/[¡|]/g, 'I') // Replace ¡ or | with I
        .replace(/[¢]/g, 'c')  // Replace ¢ with c
        .replace(/[£]/g, 'E')  // Replace £ with E
        .replace(/[¥]/g, 'Y')  // Replace ¥ with Y
        .replace(/[§]/g, 'S')  // Replace § with S
        .replace(/[©]/g, 'c')  // Replace © with c
        .replace(/[®]/g, 'R')  // Replace ® with R
        .replace(/[°]/g, '0')  // Replace ° with 0
        .replace(/[±]/g, '+')  // Replace ± with +
        .replace(/[µ]/g, 'u')  // Replace µ with u
        .replace(/[¿]/g, '?')  // Replace ¿ with ?
        .replace(/[—]/g, '-')  // Replace em dash with hyphen
        .replace(/[–]/g, '-')  // Replace en dash with hyphen
        .replace(/['']/g, "'") // Replace curly quotes with straight quotes
        .replace(/[""]/g, '"') // Replace curly double quotes with straight quotes
        
        // Fix common spacing issues
        .replace(/\s+/g, ' ')  // Replace multiple spaces with a single space
        
        // Fix common number/letter confusions
        .replace(/(\b)0(\b)/g, 'O') // Replace standalone 0 with O
        .replace(/(\b)1(\b)/g, 'I') // Replace standalone 1 with I
        .replace(/(\b)5(\b)/g, 'S') // Replace standalone 5 with S
        .replace(/(\b)8(\b)/g, 'B') // Replace standalone 8 with B
        
        // Fix common date formats
        .replace(/(\d{1,2})[.,](\d{1,2})[.,](\d{2,4})/g, '$1/$2/$3'); // Replace periods/commas in dates with slashes
    
    // Apply language-specific corrections
    switch (language.toLowerCase()) {
        case 'spanish':
            processedText = processedText
                .replace(/n~/g, 'ñ')
                .replace(/N~/g, 'Ñ')
                .replace(/(\b)a(\b)/g, 'á') // Common error in Spanish OCR
                .replace(/(\b)e(\b)/g, 'é')
                .replace(/(\b)o(\b)/g, 'ó');
            break;
        
        case 'french':
            processedText = processedText
                .replace(/a`/g, 'à')
                .replace(/e`/g, 'è')
                .replace(/e'/g, 'é')
                .replace(/c,/g, 'ç')
                .replace(/A`/g, 'À')
                .replace(/E`/g, 'È')
                .replace(/E'/g, 'É')
                .replace(/C,/g, 'Ç');
            break;
            
        case 'german':
            processedText = processedText
                .replace(/a"/g, 'ä')
                .replace(/o"/g, 'ö')
                .replace(/u"/g, 'ü')
                .replace(/A"/g, 'Ä')
                .replace(/O"/g, 'Ö')
                .replace(/U"/g, 'Ü')
                .replace(/ss/g, 'ß'); // Common OCR error for German
            break;
            
        case 'arabic':
            // Fix common Arabic OCR errors
            processedText = processedText
                .replace(/\s+/g, ' ')  // Arabic has specific spacing issues
                .replace(/[٠١٢٣٤٥٦٧٨٩]/g, function(m) {
                    return String.fromCharCode(m.charCodeAt(0) - 1632 + 48); // Convert Arabic numerals to Latin
                });
            break;
            
        case 'russian':
            // Fix common Cyrillic OCR errors
            processedText = processedText
                .replace(/bl/g, 'ы') // Common confusion in Cyrillic
                .replace(/bI/g, 'ы')
                .replace(/I0/g, 'ю')
                .replace(/I-0/g, 'ю');
            break;
            
        case 'chinese':
        case 'japanese':
        case 'korean':
            // For CJK languages, focus on improving spacing and punctuation
            processedText = processedText
                .replace(/\s+/g, '') // Remove unnecessary spaces in CJK text
                .replace(/．/g, '.') // Normalize full-width punctuation
                .replace(/，/g, ',')
                .replace(/：/g, ':')
                .replace(/；/g, ';')
                .replace(/！/g, '!')
                .replace(/？/g, '?');
            break;
    }
    
    // Remove excessive line breaks
    processedText = processedText.replace(/\n{3,}/g, '\n\n');
    
    // Final cleanup for all languages
    processedText = processedText
        .replace(/^\s+|\s+$/g, '') // Trim leading/trailing whitespace
        .replace(/\s+\./g, '.') // Fix spacing before periods
        .replace(/\s+,/g, ',') // Fix spacing before commas
        .replace(/\s+:/g, ':') // Fix spacing before colons
        .replace(/\s+;/g, ';'); // Fix spacing before semicolons
    
    return processedText;
}

// Helper function to log customer activities
async function logCustomerActivity(activityData) {
    try {
        const {
            customer_id,
            customer_name,
            actor,
            actor_type,
            action,
            purpose,
            timestamp,
            legal_basis = 'Legitimate interest'
        } = activityData;
        
        await pool.execute(
            `INSERT INTO customer_activities (
                customer_id, 
                customer_name, 
                actor, 
                actor_type, 
                action, 
                purpose, 
                timestamp, 
                legal_basis
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                customer_id,
                customer_name,
                actor,
                actor_type,
                action,
                purpose,
                timestamp || new Date(),
                legal_basis
            ]
        );
        
        return true;
    } catch (error) {
        console.error('Error logging customer activity:', error);
        return false;
    }
}

// Helper functions to parse extracted text
function parseIndividualDocumentText(text) {
    // Initialize extracted data with default empty values
    const extractedData = {
        fullName: '',
        dateOfBirth: '',
        nationality: '',
        countryOfResidence: '',
        nationalIdNumber: '',
        nationalIdExpiry: '',
        passportNumber: '',
        passportExpiry: '',
        address: '',
        city: '',
        zipCode: '',
        contactNumber: '',
        email: ''
    };
    
    // Log the raw text for debugging
    console.log("Raw extracted text:", text.substring(0, 500) + "...");
    
    // Convert text to lowercase for case-insensitive matching
    const lowerText = text.toLowerCase();
    const lines = text.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    
    // Check if this is a UAE ID card
    const isUaeIdCard = text.includes('United Arab Emirates') && 
                       (text.includes('Identity Card') || text.includes('ID Card'));
    
    // Special handling for UAE ID cards
    if (isUaeIdCard) {
        console.log("Detected UAE ID Card - using specialized extraction");
        
        // Extract full name - UAE ID format often has "Name: [Full Name]" or similar pattern
        const uaeNamePatterns = [
            /Name[;:\s]+([A-Za-z\s.'-]+)/i,
            /Name[;:\s]+([A-Za-z\s.'-]+)\s+[A-Za-z]+/i,  // Capture name before nationality/other field
            /Name[;:\s]+([^0-9\n]+?)(?=Nation|Date|ID)/i  // Capture until next field
        ];
        
        for (const pattern of uaeNamePatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.fullName = match[1].trim();
                console.log("Found UAE card name:", extractedData.fullName);
                break;
            }
        }
        
        // If name not found with patterns, try to find it from specific lines
        if (!extractedData.fullName) {
            // In UAE ID cards, the name often appears after "Name:" or similar text
            for (let i = 0; i < lines.length; i++) {
                if (lines[i].toLowerCase().includes('name')) {
                    // Name might be on this line or the next
                    const nameLine = lines[i].replace(/name[;:\s]*/i, '').trim();
                    if (nameLine && nameLine.length > 3) {
                        extractedData.fullName = nameLine;
                        console.log("Found UAE card name from line:", extractedData.fullName);
                        break;
                    } else if (i + 1 < lines.length) {
                        // Check next line if this line only has "Name:"
                        extractedData.fullName = lines[i + 1].trim();
                        console.log("Found UAE card name from next line:", extractedData.fullName);
                        break;
                    }
                }
            }
        }
        
        // Extract UAE ID number - format is typically XXX-YYYY-ZZZZZZZ-Z
        const uaeIdPatterns = [
            /(\d{3}-\d{4}-\d{7}-\d)/,  // Standard UAE ID format
            /ID[:\s#]*(\d{3}-\d{4}-\d{7}-\d)/i,
            /Number[:\s#]*(\d{3}-\d{4}-\d{7}-\d)/i,
            /(\d{3}[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d)/  // More flexible pattern
        ];
        
        for (const pattern of uaeIdPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.nationalIdNumber = match[1].trim();
                console.log("Found UAE ID number:", extractedData.nationalIdNumber);
                break;
            }
        }
        
        // Extract nationality - for UAE cards, it's often explicitly stated
        if (text.includes('Nationality:')) {
            const nationalityMatch = text.match(/Nationality[:\s]+([A-Za-z\s]+)/i);
            if (nationalityMatch && nationalityMatch[1]) {
                extractedData.nationality = nationalityMatch[1].trim();
                // Also use as country of residence if not found separately
                extractedData.countryOfResidence = extractedData.nationality;
                console.log("Found UAE card nationality:", extractedData.nationality);
            }
        }
        
        // Extract date of birth - UAE format may be different
        const uaeDobPatterns = [
            /Date of Birth[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
            /DOB[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
            /Birth Date[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i
        ];
        
        for (const pattern of uaeDobPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                try {
                    const date = new Date(match[1]);
                    if (!isNaN(date.getTime())) {
                        extractedData.dateOfBirth = date.toISOString().split('T')[0];
                    } else {
                        extractedData.dateOfBirth = match[1].trim();
                    }
                    console.log("Found UAE card DOB:", extractedData.dateOfBirth);
                } catch (e) {
                    extractedData.dateOfBirth = match[1].trim();
                }
                break;
            }
        }
        
        // Extract expiry date
        const uaeExpiryPatterns = [
            /Expiry[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
            /Valid Until[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
            /Expiration[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i
        ];
        
        for (const pattern of uaeExpiryPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                try {
                    const date = new Date(match[1]);
                    if (!isNaN(date.getTime())) {
                        extractedData.nationalIdExpiry = date.toISOString().split('T')[0];
                    } else {
                        extractedData.nationalIdExpiry = match[1].trim();
                    }
                    console.log("Found UAE card expiry:", extractedData.nationalIdExpiry);
                } catch (e) {
                    extractedData.nationalIdExpiry = match[1].trim();
                }
                break;
            }
        }
    } else {
        // Standard extraction for non-UAE ID documents
        // Extract full name - look for common patterns
        const namePatterns = [
            /name[:\s]+([A-Za-z\s.'-]+)/i,
            /full name[:\s]+([A-Za-z\s.'-]+)/i,
            /([A-Za-z\s.'-]+)\s+(?=dob|date of birth|birth|born)/i,
            /surname[:\s]+([A-Za-z\s.'-]+)/i,
            /given name[s]?[:\s]+([A-Za-z\s.'-]+)/i
        ];
        
        // Try to find name in the text
        for (const pattern of namePatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.fullName = match[1].trim();
                console.log("Found name:", extractedData.fullName);
                break;
            }
        }
        
        // If no name found yet, try looking for lines that might contain names
        if (!extractedData.fullName) {
            for (const line of lines) {
                if (line.match(/^[A-Z][a-z]+ [A-Z][a-z]+$/)) {
                    // Looks like a "FirstName LastName" format
                    extractedData.fullName = line;
                    console.log("Found potential name from line:", line);
                    break;
                }
            }
        }
    }
    
    // Common extraction for all document types - these will run regardless of document type
    // but will only overwrite values if they haven't been set by document-specific extraction
    
    // Extract date of birth if not already found
    if (!extractedData.dateOfBirth) {
        const dobPatterns = [
            /(?:date of birth|dob|born on|birth date)[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
            /(?:date of birth|dob|born on|birth date)[:\s]+([A-Za-z]+\s+[0-9]{1,2},?\s+[0-9]{2,4})/i,
            /dob[:\s]*([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
            /birth[:\s]*([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i
        ];
        
        for (const pattern of dobPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                try {
                    const date = new Date(match[1]);
                    if (!isNaN(date.getTime())) {
                        extractedData.dateOfBirth = date.toISOString().split('T')[0];
                    } else {
                        extractedData.dateOfBirth = match[1].trim();
                    }
                    console.log("Found DOB:", extractedData.dateOfBirth);
                } catch (e) {
                    extractedData.dateOfBirth = match[1].trim();
                    console.log("Found DOB (raw):", extractedData.dateOfBirth);
                }
                break;
            }
        }
    }
    
    // Extract passport number if not already found
    if (!extractedData.passportNumber) {
        const passportPatterns = [
            /passport[:\s#]+([A-Z0-9]+)/i,
            /passport number[:\s]+([A-Z0-9]+)/i,
            /passport no[:\s\.]+([A-Z0-9]+)/i,
            /document number[:\s]+([A-Z0-9]+)/i
        ];
        
        for (const pattern of passportPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.passportNumber = match[1].trim();
                console.log("Found passport number:", extractedData.passportNumber);
                break;
            }
        }
    }
    
    // Extract passport expiry if not already found
    if (!extractedData.passportExpiry) {
        const passportExpiryPatterns = [
            /(?:passport expiry|expiry date|date of expiry|expiration)[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
            /(?:valid until|valid to|expiry)[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
            /(?:expiry|exp)[:\s]*([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i
        ];
        
        for (const pattern of passportExpiryPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                try {
                    const date = new Date(match[1]);
                    if (!isNaN(date.getTime())) {
                        extractedData.passportExpiry = date.toISOString().split('T')[0];
                    } else {
                        extractedData.passportExpiry = match[1].trim();
                    }
                    console.log("Found passport expiry:", extractedData.passportExpiry);
                } catch (e) {
                    extractedData.passportExpiry = match[1].trim();
                    console.log("Found passport expiry (raw):", extractedData.passportExpiry);
                }
                break;
            }
        }
    }
    
    // Extract ID number if not already found
    if (!extractedData.nationalIdNumber) {
        const idPatterns = [
            /(?:id|identification|national id)[:\s#]+([A-Z0-9-]+)/i,
            /(?:id|identification|national id) number[:\s]+([A-Z0-9-]+)/i,
            /(?:identity card|id card)[:\s#]+([A-Z0-9-]+)/i,
            /(?:identity no|id no)[:\s\.]+([A-Z0-9-]+)/i
        ];
        
        for (const pattern of idPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.nationalIdNumber = match[1].trim();
                console.log("Found ID number:", extractedData.nationalIdNumber);
                break;
            }
        }
    }
    
    // Extract address if not already found
    if (!extractedData.address) {
        const addressPatterns = [
            /address[:\s]+([A-Za-z0-9\s.,#'\-]+)(?=\n|city|zip|postal)/i,
            /(?:residential|permanent) address[:\s]+([A-Za-z0-9\s.,#'\-]+)(?=\n|city|zip|postal)/i,
            /(?:street|location)[:\s]+([A-Za-z0-9\s.,#'\-]+)/i
        ];
        
        for (const pattern of addressPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.address = match[1].trim();
                console.log("Found address:", extractedData.address);
                break;
            }
        }
    }
    
    // Extract email if not already found
    if (!extractedData.email) {
        const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/;
        const emailMatch = text.match(emailPattern);
        if (emailMatch) {
            extractedData.email = emailMatch[0];
            console.log("Found email:", extractedData.email);
        }
    }
    
    // Extract phone number if not already found
    if (!extractedData.contactNumber) {
        const phonePatterns = [
            /(?:phone|tel|telephone|contact|mobile)[:\s]+([0-9+\-\(\)\s]{7,})/i,
            /\b(\+?[0-9]{1,3}[\s\-]?[0-9]{3}[\s\-]?[0-9]{3}[\s\-]?[0-9]{4})\b/,
            /(?:phone|tel|telephone|contact|mobile)[:\s]*([0-9+\-\(\)\s]{7,})/i
        ];
        
        for (const pattern of phonePatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.contactNumber = match[1].trim().replace(/\s+/g, '');
                console.log("Found phone number:", extractedData.contactNumber);
                break;
            }
        }
    }
    
    // Extract city if not already found
    if (!extractedData.city) {
        const cityPatterns = [
            /city[:\s]+([A-Za-z\s.'\-]+)/i,
            /town[:\s]+([A-Za-z\s.'\-]+)/i,
            /(?:city|town)[:\s]*([A-Za-z\s.'\-]+)/i,
            /(?:municipality|district)[:\s]+([A-Za-z\s.'-]+)/i
        ];
        
        for (const pattern of cityPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.city = match[1].trim();
                console.log("Found city:", extractedData.city);
                break;
            }
        }
    }
    
    // Extract zip/postal code if not already found
    if (!extractedData.zipCode) {
        const zipPatterns = [
            /(?:zip|postal|post)[:\s]+([A-Z0-9\s-]+)/i,
            /(?:zip|postal|post) code[:\s]+([A-Z0-9\s-]+)/i,
            /(?:zip|postal|post)[:\s]*([A-Z0-9\s-]+)/i
        ];
        
        for (const pattern of zipPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                extractedData.zipCode = match[1].trim();
                console.log("Found zip code:", extractedData.zipCode);
                break;
            }
        }
    }
    
    // Try to guess nationality and country of residence if not already found
    if (!extractedData.nationality || !extractedData.countryOfResidence) {
        const countryPatterns = [
            /nationality[:\s]+([A-Za-z\s]+)/i,
            /citizen(?:ship)? of[:\s]+([A-Za-z\s]+)/i,
            /country[:\s]+([A-Za-z\s]+)/i,
            /nationality[:\s]*([A-Za-z\s]+)/i,
            /citizen(?:ship)?[:\s]*([A-Za-z\s]+)/i
        ];
        
        for (const pattern of countryPatterns) {
            const match = text.match(pattern);
            if (match && match[1]) {
                const country = match[1].trim();
                
                // If we haven't found nationality yet, use this
                if (!extractedData.nationality) {
                    extractedData.nationality = country;
                    console.log("Found nationality:", extractedData.nationality);
                }
                
                // If we haven't found country of residence yet, use this
                if (!extractedData.countryOfResidence) {
                    extractedData.countryOfResidence = country;
                    console.log("Found country of residence:", extractedData.countryOfResidence);
                }
            }
        }
    }
    
    // Log the final extracted data
    console.log("Final extracted data:", extractedData);
    
    return extractedData;
}

function parseCompanyDocumentText(text) {
    // Initialize extracted data with default empty values
    const extractedData = {
        companyName: '',
        registrationNumber: '',
        incorporationDate: '',
        businessNature: '',
        registeredAddress: '',
        city: '',
        postalCode: '',
        contactEmail: '',
        contactPhone: '',
        taxNumber: ''
    };
    
    // Log the raw text for debugging
    console.log("Raw company document text:", text.substring(0, 500) + "...");
    
    // Split text into lines for line-by-line analysis
    const lines = text.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    
    // Extract company name
    const companyNamePatterns = [
        /company name[:\s]+([A-Za-z0-9\s.,'&-]+)(?=\n|reg|inc)/i,
        /name of (?:the )?company[:\s]+([A-Za-z0-9\s.,'&-]+)(?=\n|reg|inc)/i,
        /registered as[:\s]+([A-Za-z0-9\s.,'&-]+)(?=\n|reg|inc)/i,
        /business name[:\s]+([A-Za-z0-9\s.,'&-]+)/i,
        /corporate name[:\s]+([A-Za-z0-9\s.,'&-]+)/i
    ];
    
    for (const pattern of companyNamePatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            extractedData.companyName = match[1].trim();
            console.log("Found company name:", extractedData.companyName);
            break;
        }
    }
    
    // If no company name found yet, try to find the first line that might be a company name
    if (!extractedData.companyName) {
        for (const line of lines) {
            const trimmed = line.trim();
            // Look for lines that might be company names (capitalized, contains common company suffixes)
            if (/^[A-Z]/.test(trimmed) && 
                /(?:LLC|Inc|Ltd|Limited|Corporation|Corp|Company|Co\.|GmbH|SA|SRL|BV)/.test(trimmed)) {
                extractedData.companyName = trimmed;
                console.log("Found potential company name from line:", trimmed);
                break;
            }
        }
    }
    
    // Extract registration number
    const regNoPatterns = [
        /(?:registration|company|reg\.?) (?:no|num|number)[:\s#]+([A-Z0-9-]+)/i,
        /(?:registration|company|reg\.?)[:\s#]+([A-Z0-9-]+)/i,
        /(?:business|commercial) register[:\s#]+([A-Z0-9-]+)/i,
        /company (?:id|identifier)[:\s#]+([A-Z0-9-]+)/i
    ];
    
    for (const pattern of regNoPatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            extractedData.registrationNumber = match[1].trim();
            console.log("Found registration number:", extractedData.registrationNumber);
            break;
        }
    }
    
    // Extract incorporation date
    const incDatePatterns = [
        /(?:incorporation|established|founded|registered) (?:date|on)[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
        /(?:incorporation|established|founded|registered) (?:date|on)[:\s]+([A-Za-z]+\s+[0-9]{1,2},?\s+[0-9]{2,4})/i,
        /(?:date of incorporation|date of registration)[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i,
        /(?:incorporation|established|founded|registered)[:\s]+([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})/i
    ];
    
    for (const pattern of incDatePatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            // Try to convert to YYYY-MM-DD format
            try {
                const date = new Date(match[1]);
                if (!isNaN(date.getTime())) {
                    extractedData.incorporationDate = date.toISOString().split('T')[0];
                } else {
                    extractedData.incorporationDate = match[1].trim();
                }
                console.log("Found incorporation date:", extractedData.incorporationDate);
            } catch (e) {
                extractedData.incorporationDate = match[1].trim();
                console.log("Found incorporation date (raw):", extractedData.incorporationDate);
            }
            break;
        }
    }
    
    // Extract business nature/activity
    const businessPatterns = [
        /(?:nature of business|business activity|principal activity)[:\s]+([A-Za-z0-9\s.,'-]+)(?=\n)/i,
        /(?:business type|company type|business nature)[:\s]+([A-Za-z0-9\s.,'-]+)(?=\n)/i,
        /(?:business|activity|sector)[:\s]+([A-Za-z0-9\s.,'-]+)/i,
        /(?:main|primary) business[:\s]+([A-Za-z0-9\s.,'-]+)/i
    ];
    
    for (const pattern of businessPatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            extractedData.businessNature = match[1].trim();
            console.log("Found business nature:", extractedData.businessNature);
            break;
        }
    }
    
    // Extract registered address
    const addressPatterns = [
        /(?:registered|business|principal|corporate) address[:\s]+([A-Za-z0-9\s.,#'-]+)(?=\n|city|zip|postal)/i,
        /address[:\s]+([A-Za-z0-9\s.,#'-]+)(?=\n|city|zip|postal)/i,
        /(?:headquarters|main office)[:\s]+([A-Za-z0-9\s.,#'-]+)/i,
        /(?:location|premises)[:\s]+([A-Za-z0-9\s.,#'-]+)/i
    ];
    
    for (const pattern of addressPatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            extractedData.registeredAddress = match[1].trim();
            console.log("Found registered address:", extractedData.registeredAddress);
            break;
        }
    }
    
    // Extract email
    const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/;
    const emailMatch = text.match(emailPattern);
    if (emailMatch) {
        extractedData.contactEmail = emailMatch[0];
        console.log("Found email:", extractedData.contactEmail);
    }
    
    // Extract phone number
    const phonePatterns = [
        /(?:phone|tel|telephone|contact)[:\s]+([0-9+\-\(\)\s]{7,})/i,
        /\b(\+?[0-9]{1,3}[\s\-]?[0-9]{3}[\s\-]?[0-9]{3}[\s\-]?[0-9]{4})\b/
    ];
    
    for (const pattern of phonePatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            extractedData.contactPhone = match[1].trim().replace(/\s+/g, '');
            console.log("Found phone number:", extractedData.contactPhone);
            break;
        }
    }
    
    // Extract city
    const cityPattern = /city[:\s]+([A-Za-z\s.'-]+)/i;
    const cityMatch = text.match(cityPattern);
    if (cityMatch && cityMatch[1]) {
        extractedData.city = cityMatch[1].trim();
    }
    
    // Extract zip/postal code
    const zipPatterns = [
        /(?:zip|postal|post)[:\s]+([A-Z0-9\s-]+)/i,
        /(?:zip|postal|post) code[:\s]+([A-Z0-9\s-]+)/i
    ];
    
    for (const pattern of zipPatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            extractedData.postalCode = match[1].trim();
            console.log("Found postal code:", extractedData.postalCode);
            break;
        }
    }
    
    // Extract tax number
    const taxPatterns = [
        /(?:tax|vat|tin|ein) (?:no|num|number|id|identification)[:\s#]+([A-Z0-9-]+)/i,
        /(?:tax|vat|tin|ein)[:\s#]+([A-Z0-9-]+)/i,
        /(?:fiscal code|tax code)[:\s#]+([A-Z0-9-]+)/i
    ];
    
    for (const pattern of taxPatterns) {
        const match = text.match(pattern);
        if (match && match[1]) {
            extractedData.taxNumber = match[1].trim();
            console.log("Found tax number:", extractedData.taxNumber);
            break;
        }
    }
    
    // Log the final extracted data
    console.log("Final extracted company data:", extractedData);
    
    return extractedData;
}

// --- Self-Link Onboarding Endpoints ---
app.post('/api/registerIndividualSelfLink', requireAuth, checkAndConsumeCredit, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const {
            fullName,
            email,
            // ... other fields ...
            extractedData // Include the extracted data from document
        } = req.body;
        
        // Store the data in the database similar to regular individual onboarding
        // but also include information about the uploaded document
        
        const [result] = await pool.execute(
            `INSERT INTO individualob (
                full_name, email, resident_status, gender, date_of_birth, 
                nationality, country_of_residence, other_nationalities, 
                specified_other_nationalities, national_id_number, national_id_expiry,
                passport_number, passport_expiry, address, state, city, zip_code,
                contact_number, dialing_code, work_type, industry, product_type_offered,
                product_offered, company_name, position_in_company, onboarded_by,
                onboarded_at, document_type, has_uploaded_document
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, 1)`,
            [
                fullName, email, req.body.residentStatus || null, req.body.gender || null, 
                req.body.dateOfBirth || null, req.body.nationality || null, 
                req.body.countryOfResidence || null, req.body.otherNationalities ? 1 : 0,
                req.body.specifiedOtherNationalities || null, req.body.nationalIdNumber || null,
                req.body.nationalIdExpiry || null, req.body.passportNumber || null,
                req.body.passportExpiry || null, req.body.address || null, req.body.state || null,
                req.body.city || null, req.body.zipCode || null, req.body.contactNumber || null,
                req.body.dialingCode || null, req.body.workType || null, req.body.industry || null,
                req.body.productTypeOffered || null, req.body.productOffered || null,
                req.body.companyName || null, req.body.positionInCompany || null,
                req.session.user.name || 'Self-Service',
                extractedData?.documentType || 'unknown'
            ]
        );
        
        const customerId = result.insertId;
        
        // Log the activity
        await logCustomerActivity({
            customer_id: customerId,
            customer_name: fullName,
            actor: req.session.user.name || 'Self-Service',
            actor_type: 'user',
            action: 'Registered new individual customer via self-service',
            purpose: 'Customer Self-Onboarding',
            timestamp: new Date()
        });
        
        res.status(201).json({ 
            message: 'Individual registration successful', 
            id: customerId 
        });
    } catch (error) {
        console.error('Error registering individual via self-link:', error);
        res.status(500).json({ message: 'Registration failed' });
    }
});

app.post('/api/registerCompanySelfLink', requireAuth, checkAndConsumeCredit, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const formData = req.body;
        const extractedData = formData.extractedData;
        
        // Store the company data in the database similar to regular company onboarding
        // but also include information about the uploaded document
        
        const [result] = await pool.execute(
            `INSERT INTO companyob (
                company_name, registration_number, company_type, incorporation_date,
                business_nature, industry_sector, annual_turnover, employee_count,
                website_url, registered_address, operating_address, country, state,
                city, postal_code, contact_person_name, contact_email, contact_phone,
                tax_number, regulatory_licenses, onboarded_by, onboarded_at,
                document_type, has_uploaded_document
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, 1)`,
            [
                formData.companyName, formData.registrationNumber, formData.companyType,
                formData.incorporationDate, formData.businessNature, formData.industrySector,
                formData.annualTurnover, formData.employeeCount, formData.websiteUrl,
                formData.registeredAddress, formData.operatingAddress, formData.country,
                formData.state, formData.city, formData.postalCode, formData.contactPersonName,
                formData.contactEmail, formData.contactPhone, formData.taxNumber,
                formData.regulatoryLicenses, req.session.user.name || 'Self-Service',
                extractedData?.documentType || 'unknown'
            ]
        );
        
        const companyId = result.insertId;
        
        // Log the activity
        await logCustomerActivity({
            customer_id: companyId,
            customer_name: formData.companyName,
            actor: req.session.user.name || 'Self-Service',
            actor_type: 'user',
            action: 'Registered new company via self-service',
            purpose: 'Company Self-Onboarding',
            timestamp: new Date()
        });
        
        res.status(201).json({ 
            message: 'Company registration successful', 
            id: companyId 
        });
    } catch (error) {
        console.error('Error registering company via self-link:', error);
        res.status(500).json({ message: 'Registration failed' });
    }
});

// --- Start Server ---
app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});

// Helper function to detect language from text
async function detectTextLanguage(text) {
    try {
        // This is a simple language detection based on character frequency
        // For production, consider using a proper language detection library
        
        // Count characters by script groups
        const latinChars = (text.match(/[a-zA-Z]/g) || []).length;
        const cyrillicChars = (text.match(/[а-яА-ЯёЁ]/g) || []).length;
        const arabicChars = (text.match(/[\u0600-\u06FF]/g) || []).length;
        const chineseChars = (text.match(/[\u4E00-\u9FFF]/g) || []).length;
        const japaneseChars = (text.match(/[\u3040-\u309F\u30A0-\u30FF]/g) || []).length;
        const koreanChars = (text.match(/[\uAC00-\uD7AF\u1100-\u11FF]/g) || []).length;
        const devanagariChars = (text.match(/[\u0900-\u097F]/g) || []).length;
        
        // Get the script with the highest character count
        const scripts = [
            { script: 'latin', count: latinChars },
            { script: 'cyrillic', count: cyrillicChars },
            { script: 'arabic', count: arabicChars },
            { script: 'chinese', count: chineseChars },
            { script: 'japanese', count: japaneseChars },
            { script: 'korean', count: koreanChars },
            { script: 'devanagari', count: devanagariChars }
        ];
        
        scripts.sort((a, b) => b.count - a.count);
        
        // If the dominant script is Latin, try to determine specific Latin-based language
        if (scripts[0].script === 'latin' && latinChars > 0) {
            // Count specific character patterns for different Latin-based languages
            const spanishChars = (text.match(/[áéíóúüñ]/gi) || []).length;
            const frenchChars = (text.match(/[àâäæçéèêëîïôœùûüÿ]/gi) || []).length;
            const germanChars = (text.match(/[äöüß]/gi) || []).length;
            const italianChars = (text.match(/[àèéìíîòóùú]/gi) || []).length;
            
            const latinLanguages = [
                { lang: 'eng', count: latinChars - (spanishChars + frenchChars + germanChars + italianChars) },
                { lang: 'spa', count: spanishChars },
                { lang: 'fra', count: frenchChars },
                { lang: 'deu', count: germanChars },
                { lang: 'ita', count: italianChars }
            ];
            
            latinLanguages.sort((a, b) => b.count - a.count);
            
            return latinLanguages[0].lang;
        }
        
        // Map the dominant script to a language code
        return mapScriptToLanguage(scripts[0].script);
    } catch (error) {
        console.error('Error detecting language:', error);
        return 'eng'; // Default to English on error
    }
}

// Helper function to map script to language code
function mapScriptToLanguage(script) {
    const scriptToLang = {
        'latin': 'eng',
        'cyrillic': 'rus',
        'arabic': 'ara',
        'chinese': 'chi_sim',
        'japanese': 'jpn',
        'korean': 'kor',
        'devanagari': 'hin'
    };
    
    return scriptToLang[script.toLowerCase()] || 'eng';
}

// Updating the registerIndividual route to handle file upload
app.post('/registerIndividual', requireAuth, recordProfileCredit, upload.single('passportImage'), async (req, res) => {
    try {
        // Get form fields from req.body
        const {
            fullName, email, residentStatus, gender, dateOfBirth, nationality, countryOfResidence,
            otherNationalities, specifiedOtherNationalities, nationalIdNumber, nationalIdExpiry,
            passportNumber, passportExpiry, address, state, city, zipCode, contactNumber,
            dialingCode, workType, industry, productTypeOffered, productOffered, companyName, positionInCompany
        } = req.body;

        // Basic validation
        if (!fullName || !email) {
            return res.status(400).json({ message: 'Full name and email are required fields.' });
        }

        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format.' });
        }
        
        // Get user ID from session
        const userId = req.session.userId;
        
        // Start a transaction
        const connection = await pool.getConnection();
        await connection.beginTransaction();
        
        try {
            // Passport image file info
            let passportImagePath = null;
            if (req.file) {
                passportImagePath = req.file.path;
            }
            
            // Insert individual profile into database
            const [result] = await connection.execute(
                `INSERT INTO individualob 
                (user_id, full_name, email, resident_status, gender, date_of_birth, nationality, 
                country_of_residence, other_nationalities, specified_other_nationalities, 
                national_id_number, national_id_expiry, passport_number, passport_expiry,
                passport_image_path, address, state, city, zip_code, contact_number, 
                dialing_code, work_type, industry, product_type_offered, product_offered, company_name, 
                position_in_company, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    userId, fullName, email, residentStatus, gender, dateOfBirth, nationality,
                    countryOfResidence, otherNationalities === 'true' ? 1 : 0, specifiedOtherNationalities,
                    nationalIdNumber, nationalIdExpiry, passportNumber, passportExpiry, 
                    passportImagePath, address, state, city, zipCode, contactNumber,
                    dialingCode, workType, industry, productTypeOffered, productOffered, companyName,
                    positionInCompany
                ]
            );

            const profileId = result.insertId;
            
            // Log activity
            await logCustomerActivity({
                userId,
                action: 'register_individual',
                details: `Registered individual profile: ${fullName} (${email})`,
                relatedId: profileId,
                profileType: 'individual'
            });

            // Commit the transaction
            await connection.commit();
            
            res.status(201).json({ 
                message: 'Individual profile registered successfully', 
                profileId 
            });
            
        } catch (error) {
            // Rollback in case of error
            await connection.rollback();
            console.error('Error registering individual profile:', error);
            res.status(500).json({ message: 'Failed to register individual profile', error: error.message });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Error handling individual registration:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Add route to serve uploaded passport images
app.get('/uploads/:filename', requireAuth, (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'uploads', filename);
    
    res.sendFile(filePath, (err) => {
        if (err) {
            console.error('Error sending file:', err);
            res.status(404).json({ message: 'File not found' });
        }
    });
});