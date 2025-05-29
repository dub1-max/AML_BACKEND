// Cloudflare configuration
module.exports = {
    // Enable Cloudflare flexible SSL
    ssl: {
        rewrite: true,
        enabled: true
    },
    // Security headers
    headers: {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
    },
    // Cache settings
    cache: {
        browser: {
            serviceworker: {
                enabled: true
            }
        },
        edge: {
            enabled: true
        }
    }
}; 