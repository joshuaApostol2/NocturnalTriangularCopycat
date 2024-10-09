const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const app = express();
const port = 3000;

const CLOUDFLARE_API_KEY = 'jR_QLJkhgWLtCJsMRFHUtnMIoQzSO4PNyJ_AwiWZ';
const CLOUDFLARE_ZONE_ID = '4de7cfa4c579eba6a1bc257bf61b9c6e';
const blocklist = new Set();
const requestCounters = new Map();
const RATE_LIMIT = 40;
const BAN_THRESHOLD = 100;
const IP_BLOCK_THRESHOLD = 5;

const proxyHeaders = [
    'x-forwarded-for', 'via', 'x-real-ip', 'forwarded', 
    'x-client-ip', 'x-forwarded', 'proxy-connection', 'x-forwarded-proto'
];

const verifyCloudflareToken = async () => {
    try {
        const response = await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
                'Content-Type': 'application/json'
            }
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
            configuration: { target: 'ip', value: ip },
            notes: 'Blocking malicious IP'
        }, {
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });
    } catch {}
};

const isBannedIP = (ip) => blocklist.has(ip);

const checkRequestRate = (ip) => {
    if (!requestCounters.has(ip)) {
        requestCounters.set(ip, { count: 1, lastRequest: Date.now(), banCount: 0 });
        return true;
    }
    const counter = requestCounters.get(ip);
    const timeDiff = (Date.now() - counter.lastRequest) / 1000;

    if (timeDiff > 60) {
        counter.count = 1;
        counter.lastRequest = Date.now();
        return true;
    }
    if (counter.count >= BAN_THRESHOLD) {
        counter.banCount++;
        if (counter.banCount >= IP_BLOCK_THRESHOLD) {
            blocklist.add(ip);
            blockIPCloudflare(ip);
        }
        return false;
    }
    if (counter.count >= RATE_LIMIT) {
        return false;
    }
    counter.count++;
    return true;
};

const detectAndBanIP = async (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.connection.remoteAddress;

    if (isBannedIP(ip)) return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    if (!checkRequestRate(ip)) return res.status(429).send('hina ng DDoS mo bata HAHAHAHA');

    for (const header of proxyHeaders) {
        if (req.headers[header]) {
            blocklist.add(ip);
            blockIPCloudflare(ip);
            return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
        }
    }

    const userAgent = req.headers['user-agent'];
    const isBlockedUserAgent = userAgent.includes('curl') || userAgent.includes('wget') || userAgent.includes('bot') || userAgent.includes('HTTPClient');
    const isBlockedIP = ip.includes('127.0.0.1') || ip.includes('0.0.0.0');

    if (isBlockedUserAgent || isBlockedIP) {
        blocklist.add(ip);
        blockIPCloudflare(ip);
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    if (req.headers['content-length'] > 8000) {
        return res.status(413).send('hina ng DDoS mo bata HAHAHAHA');
    }

    if (req.headers.origin && req.headers.origin !== 'https://anti-ddos-2by0.onrender.com') {
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }
    
    if (req.body && Object.keys(req.body).length > 10) {
        return res.status(400).send('hina ng DDoS mo bata HAHAHAHA');
    }

    next();
};

const rateLimitMiddleware = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.connection.remoteAddress;
    const currentTime = Date.now();
    const windowTime = 60 * 1000;

    if (!requestCounters.has(ip)) {
        requestCounters.set(ip, { count: 1, lastRequest: currentTime });
    } else {
        const counter = requestCounters.get(ip);
        if (currentTime - counter.lastRequest > windowTime) {
            counter.count = 1;
            counter.lastRequest = currentTime;
        } else {
            counter.count++;
            if (counter.count > RATE_LIMIT) {
                return res.status(429).send('hina ng DDoS mo bata HAHAHAHA');
            }
        }
    }
    next();
};

app.use(helmet());
app.use(express.json());
app.use(rateLimitMiddleware);
app.use(detectAndBanIP);

app.get('/', (req, res) => {
    res.send('hina ng DDoS mo bata HAHAHAHA');
});

app.use((req, res) => {
    res.status(404).send('Not found');
});

app.listen(port, async () => {
    const isCloudflareTokenValid = await verifyCloudflareToken();
    if (!isCloudflareTokenValid) {
        console.error('Invalid Cloudflare API key.');
    }
    console.log(`API running on port ${port}`);
});
