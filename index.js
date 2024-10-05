const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const app = express();
const port = 3000;

let blocklist = {};
const BLOCK_TIME = 15 * 60 * 1000;
const API_KEY = 'ea598429a1ea4d589669de66faa9db2c';
const CLOUDFLARE_API_KEY = 'jR_QLJkhgWLtCJsMRFHUtnMIoQzSO4PNyJ_AwiWZ';
const CLOUDFLARE_ZONE_ID = '4de7cfa4c579eba6a1bc257bf61b9c6e';
const IP_REQUEST_COUNT = {};
const MAX_REQUESTS = 100;
let isCloudflareTokenValid = false;

const checkIPReputation = async (ip) => {
    try {
        const response = await axios.get(`https://api.ipgeolocation.io/ipgeo?apiKey=${API_KEY}&ip=${ip}`);
        return response.data;
    } catch (error) {
        return null;
    }
};

const blockIPCloudflare = async (ip) => {
    try {
        await axios.post(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/firewall/access/rules`, {
            mode: 'block',
            configuration: {
                target: 'ip',
                value: ip
            },
            notes: 'Blocking malicious IP'
        }, {
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
                'Content-Type': 'application/json',
            },
        });
    } catch (error) {
        console.error(`Error blocking IP ${ip} on Cloudflare:`, error);
    }
};

const verifyCloudflareToken = async () => {
    try {
        const response = await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
                'Content-Type': 'application/json',
            },
        });
        isCloudflareTokenValid = response.data.success;
    } catch (error) {
        isCloudflareTokenValid = false;
    }
};

const isMaliciousIP = (ipData) => {
    return ipData && (ipData.is_tor || ipData.is_proxy || ipData.is_anonymous);
};

const logRequest = (req) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log(`Request from ${ip} | Method: ${req.method} | URL: ${req.url}`);
};

app.use(helmet());

app.use(async (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (blocklist[ip] && (Date.now() - blocklist[ip]) < BLOCK_TIME) {
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    const ipData = await checkIPReputation(ip);
    if (isMaliciousIP(ipData)) {
        blocklist[ip] = Date.now();
        await blockIPCloudflare(ip);
        return res.status(403).send('hina ng DDoS mo, bata HAHAHAHA');
    }

    IP_REQUEST_COUNT[ip] = (IP_REQUEST_COUNT[ip] || 0) + 1;

    if (IP_REQUEST_COUNT[ip] > MAX_REQUESTS) {
        blocklist[ip] = Date.now();
        await blockIPCloudflare(ip);
        return res.status(429).send('hina ng DDoS mo, bata HAHAHAHA');
    }

    setTimeout(() => {
        IP_REQUEST_COUNT[ip]--;
    }, 60000);

    logRequest(req);
    next();
});

app.get('/', async (req, res) => {
    if (!isCloudflareTokenValid) {
        await verifyCloudflareToken();
    }

    if (!isCloudflareTokenValid) {
        return res.status(403).send('Invalid Cloudflare API key.');
    }

    res.send('hina ng DDoS mo bata HAHAHAHA');
});

app.use((req, res) => {
    res.status(404).send('Not found');
});

app.listen(port, async () => {
    await verifyCloudflareToken();
    console.log(`API running on port ${port}`);
});
