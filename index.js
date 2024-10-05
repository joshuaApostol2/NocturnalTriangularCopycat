const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const app = express();
const port = 3000;

const blocklist = new Set();
const CLOUDFLARE_API_KEY = 'jR_QLJkhgWLtCJsMRFHUtnMIoQzSO4PNyJ_AwiWZ';
const CLOUDFLARE_ZONE_ID = '4de7cfa4c579eba6a1bc257bf61b9c6e';
const MAX_REQUESTS = 100;
const CONNECTION_LIMIT = 100;

const ipRequestCount = {};
const ipConnectionCount = {};

const verifyCloudflareToken = async () => {
    try {
        const response = await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
                'Content-Type': 'application/json',
            },
        });
        return response.data.success;
    } catch {
        return false;
    }
};

const blockIPCloudflare = async (ip) => {
    try {
        await axios.post(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/firewall/access/rules`, {
            mode: 'block',
            configuration: {
                target: 'ip',
                value: ip,
            },
            notes: 'Blocking malicious IP',
        }, {
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
                'Content-Type': 'application/json',
            },
        });
    } catch {}
};

const isBannedIP = (ip) => blocklist.has(ip);

app.use(helmet());
app.use(express.json());

const rateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: MAX_REQUESTS,
    handler: (req, res) => {
        res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    },
});

app.use(rateLimiter);

app.use(async (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    if (isBannedIP(ip)) {
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    ipRequestCount[ip] = (ipRequestCount[ip] || 0) + 1;
    ipConnectionCount[ip] = (ipConnectionCount[ip] || 0) + 1;

    if (ipRequestCount[ip] > MAX_REQUESTS || ipConnectionCount[ip] > CONNECTION_LIMIT) {
        blocklist.add(ip);
        await blockIPCloudflare(ip);
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    setTimeout(() => {
        ipRequestCount[ip]--;
    }, 60000);

    setTimeout(() => {
        ipConnectionCount[ip]--;
    }, 60000);

    next();
});

app.get('/', async (req, res) => {
    res.send('hina ng DDoS mo bata HAHAHAHA');
});

app.use((req, res) => {
    res.status(404).send('Not found');
});

app.listen(port, async () => {
    const isCloudflareTokenValid = await verifyCloudflareToken();
    if (!isCloudflareTokenValid) {
        console.error('Invalid Cloudflare API key. DDoS protection might not work.');
    }
    console.log(`API running on port ${port}`);
});
