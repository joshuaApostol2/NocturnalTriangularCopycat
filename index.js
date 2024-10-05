const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const requestIp = require('request-ip');
const puppeteer = require('puppeteer-core');

const app = express();
const port = 3000;

const CLOUDFLARE_API_KEY = 'jR_QLJkhgWLtCJsMRFHUtnMIoQzSO4PNyJ_AwiWZ';
const CLOUDFLARE_ZONE_ID = '4de7cfa4c579eba6a1bc257bf61b9c6e';

const blocklist = new Set();

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

const detectAndBanIP = (req, res, next) => {
    const ip = req.clientIp;

    if (isBannedIP(ip)) {
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    if (req.headers['x-forwarded-for']) {
        const proxies = req.headers['x-forwarded-for'].split(',');
        proxies.forEach((proxy) => {
            blocklist.add(proxy.trim());
            blockIPCloudflare(proxy.trim());
        });
    }

    blocklist.add(ip);
    blockIPCloudflare(ip);
    res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
};

const usePuppeteerToSimulateUser = async () => {
    const browser = await puppeteer.launch({
        headless: true,
    });

    const page = await browser.newPage();
    await page.goto('https://anti-ddos.onrender.com/'); 
    await browser.close();
};

app.use(helmet());
app.use(requestIp.mw());
app.use(express.json());
app.use(detectAndBanIP);

app.get('/', async (req, res) => {
    await usePuppeteerToSimulateUser();
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
