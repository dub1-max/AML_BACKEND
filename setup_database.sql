-- Create the persons table if it doesn't exist.
-- This script assumes the database 'aml_checker' already exists.

USE aml_checker;  -- Select the database

CREATE TABLE IF NOT EXISTS persons (
    name VARCHAR(255) NOT NULL,
    type VARCHAR(255),
    country VARCHAR(255),
    identifiers VARCHAR(255),
    riskLevel INT,
    sanctions TEXT,  -- Use TEXT for potentially long JSON strings
    dataset VARCHAR(255),
    lastUpdated BIGINT,
    PRIMARY KEY (name)
);

-- Optional:  You can add indexes for performance if needed.  For example:
-- CREATE INDEX idx_persons_identifiers ON persons (identifiers);
-- CREATE INDEX idx_persons_country ON persons (country);
-- CREATE INDEX idx_persons_dataset ON persons (dataset);
-- CREATE INDEX idx_persons_lastUpdated ON persons (lastUpdated);

-- The indexes are commented out by default.  Uncomment them if you find
-- that searches on those columns are slow.  Indexes speed up searches
-- but can slightly slow down inserts and updates.

-- No INSERT statements are included here. The backend (server.js) handles
-- populating the data from the CSV files. This file is *only* for
-- table creation.