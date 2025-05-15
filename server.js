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
    'http://137.184.150.6:5173'
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
    allowedHeaders: ['Content-Type', 'Authorization'],
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
    'https://data.opensanctions.org/datasets/20250205/peps/targets.simple.csv',
    'https://data.opensanctions.org/datasets/20250206/debarment/targets.simple.csv',
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
                role VARCHAR(255) NOT NULL DEFAULT 'user'
            )
        `);
        console.log("✅ Users table ready.");

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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);
        console.log("✅ companyob table ready.");

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

        req.session.user = { id: user.id, email: user.email, name: user.name, role: user.role };
        req.session.isAuthenticated = true;  // You can use this if you need it elsewhere

        res.json({ message: 'Login successful', user: { id: user.id, email: user.email, name: user.name, role: user.role } });

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

app.get('/api/auth/user', requireAuth, (req, res) => {
    res.json({ user: req.session.user });
});

// --- Person Search and Retrieval Routes ---
app.get('/api/persons/search', requireAuth, async (req, res) => {
    try {
        const { searchTerm, searchId, page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;
        
        let query = 'SELECT SQL_CALC_FOUND_ROWS * FROM persons';
        const params = [];
        
        // Only add WHERE clause if we have search parameters
        if (searchTerm || searchId) {
            query += ' WHERE 1=1';
            
            if (searchTerm) {
                query += ' AND (LOWER(name) LIKE LOWER(?) OR SOUNDEX(name) = SOUNDEX(?))';
                params.push(`%${searchTerm}%`, searchTerm);
            }
            if (searchId) {
                query += ' AND LOWER(identifiers) LIKE LOWER(?)';
                params.push(`%${searchId}%`);
            }
        }
        
        // Add pagination
        query += ' LIMIT ? OFFSET ?';
        params.push(Number(limit), Number(offset));

        console.log('Executing query:', query, 'with params:', params); // Debug log

        const connection = await pool.getConnection();
        try {
            const [rows] = await connection.execute(query, params);
            const [countResult] = await connection.execute('SELECT FOUND_ROWS() as total');
            
            console.log('Search results:', rows.length, 'total:', countResult[0].total); // Debug log

            res.json({
                data: rows,
                pagination: {
                    total: countResult[0].total,
                    page: Number(page),
                    totalPages: Math.ceil(countResult[0].total / limit)
                }
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Error searching persons:', error);
        res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
});

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
app.get('/api/tracking', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.id;
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
        res.json(rows);
    } catch (error) {
        console.error('Error fetching tracked persons:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/tracking/:name', requireAuth, async (req, res) => {
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
app.post('/api/registerIndividual', requireAuth, async (req, res) => {
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
app.post('/api/registerCompany', requireAuth, async (req, res) => {
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


        await pool.execute(insertQuery, values);
        res.status(201).json({ message: 'Company registration successful' });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: 'Contact email already registered.' });
        }
        console.error('Error during company registration:', error);
        res.status(500).json({ message: 'Internal server error' });
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

// --- Start Server ---
app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});