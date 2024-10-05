const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const app = express();
const port = 3000;

const blocklist = new Set();
const CLOUDFLARE_API_KEY = 'jR_QLJkhgWLtCJsMRFHUtnMIoQzSO4PNyJ_AwiWZ';
const CLOUDFLARE_ZONE_ID = '4de7cfa4c579eba6a1bc257bf61b9c6e';
const RECAPTCHA_SECRET_KEY = '6Lf8qlgqAAAAAE61r0lUtXaC1zDbF_c5ntud8pet';
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
            return res.status(429).send('please complete CAPTCHA');
        }

        requestCounts.set(ip, count);
    }

    next();
};

const verifyRecaptcha = async (token) => {
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
            params: {
                secret: RECAPTCHA_SECRET_KEY,
                response: token,
            },
        });
        return response.data.success;
    } catch {
        return false;
    }
};

app.use(helmet());
app.use(express.json());

app.use(rateLimiter);

app.post('/submit', async (req, res) => {
    const { token } = req.body;

    const isHuman = await verifyRecaptcha(token);
    if (!isHuman) {
        return res.status(403).send('CAPTCHA verification failed');
    }

    res.send('hina ng DDoS mo, bata HAHAHAHA');
});

app.get('/', (req, res) => {
    res.send(`
        <form action="/submit" method="post">
            <input type="hidden" id="g-recaptcha-response" name="token" value="">
            <button type="submit">Submit</button>
        </form>
        <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    `);
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
