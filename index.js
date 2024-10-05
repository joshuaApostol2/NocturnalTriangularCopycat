const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const app = express();
const port = 3000;

const CLOUDFLARE_API_KEY = 'jR_QLJkhgWLtCJsMRFHUtnMIoQzSO4PNyJ_AwiWZ';
const CLOUDFLARE_ZONE_ID = '4de7cfa4c579eba6a1bc257bf61b9c6e';

const blocklist = new Set();
const MAX_REQUESTS = 15;
const TIME_WINDOW = 60 * 1000;

const requestCounts = new Map();
const requestTimestamps = new Map();

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

const rateLimiter = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (isBannedIP(ip)) {
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    const now = Date.now();

    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, 0);
        requestTimestamps.set(ip, now);
    }

    const firstRequestTime = requestTimestamps.get(ip);

    if (now - firstRequestTime > TIME_WINDOW) {
        requestCounts.set(ip, 1);
        requestTimestamps.set(ip, now);
    } else {
        const count = requestCounts.get(ip) + 1;

        if (count > MAX_REQUESTS) {
            blocklist.add(ip);
            blockIPCloudflare(ip);
            return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
        }

        requestCounts.set(ip, count);
    }

    next();
};

const additionalSecurityChecks = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    if (userAgent && userAgent.includes('BadBot')) {
        blocklist.add(ip);
        blockIPCloudflare(ip);
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    next();
};

// Advanced Security Features
const trackRequest = (ip) => {
    const now = Date.now();
    const count = requestCounts.get(ip) || 0;

    if (count >= MAX_REQUESTS) {
        return false;
    }

    requestCounts.set(ip, count + 1);
    requestTimestamps.set(ip, now);
    return true;
};

const enforceStrictSecurity = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (!trackRequest(ip)) {
        blocklist.add(ip);
        blockIPCloudflare(ip);
        return res.status(403).send('Hina ng DDoS mo, bata HAHAHAHA');
    }

    next();
};

app.use(helmet());
app.use(express.json());
app.use(rateLimiter);
app.use(enforceStrictSecurity);
app.use(additionalSecurityChecks);

app.get('/', (req, res) => {
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
