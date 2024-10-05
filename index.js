const express = require('express');
const axios = require('axios');
const app = express();
const port = 3000;

let blocklist = {};
const BLOCK_TIME = 15 * 60 * 1000;
const API_KEY = 'ea598429a1ea4d589669de66faa9db2c';
const MAX_REQUESTS = 100;
const IP_REQUEST_COUNT = {};

const checkIPReputation = async (ip) => {
    try {
        const response = await axios.get(`https://api.ipgeolocation.io/ipgeo?apiKey=${API_KEY}&ip=${ip}`);
        return response.data;
    } catch (error) {
        return null;
    }
};

const isMaliciousIP = (ipData) => {
    return ipData && (ipData.is_tor || ipData.is_proxy || ipData.is_anonymous);
};

const captchaRequired = (req) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    return blocklist[ip] || false;
};

app.use(async (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (blocklist[ip] && (Date.now() - blocklist[ip]) < BLOCK_TIME) {
        return res.status(403).send('Hina ng DDoS mo, bata HAHAHAHA');
    }

    const ipData = await checkIPReputation(ip);
    if (isMaliciousIP(ipData)) {
        blocklist[ip] = Date.now();
        return res.status(403).send('Hina ng DDoS mo, bata HAHAHAHA');
    }

    IP_REQUEST_COUNT[ip] = (IP_REQUEST_COUNT[ip] || 0) + 1;
    if (IP_REQUEST_COUNT[ip] > MAX_REQUESTS) {
        blocklist[ip] = Date.now();
        return res.status(403).send('Hina ng DDoS mo, bata HAHAHAHA');
    }

    setTimeout(() => {
        IP_REQUEST_COUNT[ip]--;
    }, 60000);

    if (captchaRequired(req)) {
        return res.status(429).send('Please complete a CAPTCHA to continue.');
    }

    next();
});

app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'];
    const acceptHeader = req.headers['accept'];

    if (!userAgent || !acceptHeader || !/^Mozilla|Chrome|Safari/.test(userAgent)) {
        return res.status(400).send('Invalid request.');
    }

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});

app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log(`Request from ${ip} | Method: ${req.method} | URL: ${req.url}`);
    next();
});

app.get('/', (req, res) => {
    res.send('Protected API. Hina ng DDoS mo, bata HAHAHAHA');
});

app.listen(port, () => {
    console.log(`Running on port ${port}`);
});
