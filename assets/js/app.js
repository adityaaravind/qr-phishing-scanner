"use strict";
    /* ================= Analysis engine ================= */

    var BRANDS = [
      { name: "PayPal", keys: ["paypal"], domains: ["paypal.com", "paypal.me"] },
      { name: "Apple", keys: ["apple", "icloud", "appleid"], domains: ["apple.com", "icloud.com"] },
      { name: "Microsoft", keys: ["microsoft", "outlook", "live", "office365", "hotmail"], domains: ["microsoft.com", "outlook.com", "live.com", "office.com", "microsoftonline.com"] },
      { name: "Google", keys: ["google", "gmail", "youtube"], domains: ["google.com", "gmail.com", "youtube.com", "google.co.uk"] },
      { name: "Amazon", keys: ["amazon"], domains: ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazon.ca", "amazon.com.au"] },
      { name: "Netflix", keys: ["netflix"], domains: ["netflix.com"] },
      { name: "Facebook", keys: ["facebook"], domains: ["facebook.com", "fb.com"] },
      { name: "Instagram", keys: ["instagram"], domains: ["instagram.com"] },
      { name: "WhatsApp", keys: ["whatsapp"], domains: ["whatsapp.com", "wa.me"] },
      { name: "LinkedIn", keys: ["linkedin"], domains: ["linkedin.com"] },
      { name: "Chase", keys: ["chase"], domains: ["chase.com"] },
      { name: "Bank of America", keys: ["bankofamerica", "bofa"], domains: ["bankofamerica.com"] },
      { name: "Wells Fargo", keys: ["wellsfargo"], domains: ["wellsfargo.com"] },
      { name: "Binance", keys: ["binance"], domains: ["binance.com", "binance.us"] },
      { name: "Coinbase", keys: ["coinbase"], domains: ["coinbase.com"] },
      { name: "Venmo", keys: ["venmo"], domains: ["venmo.com"] },
      { name: "Cash App", keys: ["cashapp"], domains: ["cash.app"] },
      { name: "DHL", keys: ["dhl"], domains: ["dhl.com"] },
      { name: "FedEx", keys: ["fedex"], domains: ["fedex.com"] },
      { name: "USPS", keys: ["usps"], domains: ["usps.com"] },
      { name: "UPS", keys: ["ups"], domains: ["ups.com"] },
      { name: "Steam", keys: ["steam"], domains: ["steampowered.com", "steamcommunity.com"] },
      { name: "Spotify", keys: ["spotify"], domains: ["spotify.com"] },
      { name: "Adobe", keys: ["adobe"], domains: ["adobe.com"] },
      { name: "Dropbox", keys: ["dropbox"], domains: ["dropbox.com"] },
      { name: "X (Twitter)", keys: ["twitter"], domains: ["x.com", "twitter.com"] }
    ];

    var SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rb.gy","rebrand.ly","tiny.cc","s.id","bit.do","j.mp","q.gs","po.st","tr.im","wp.me","v.gd","x.co","qr.ae","adf.ly","bc.vc","u.to","snip.ly","shorturl.at","yourls.org","bl.ink","trib.al","dlvr.it","ift.tt","shorte.st","go2l.ink","budurl.com","lnk.bio","short.io","bitly.com","tiny.one","urlz.fr","rb1.site"];

    var SUS_TLDS = ["xyz","top","zip","mov","click","buzz","icu","online","site","live","fun","rest","quest","best","vip","pw","tk","ml","ga","cf","gq","cam","loan","men","party","review","cricket","science","work","support","su","monster","autos","sbs","cfd","bond","hair","beauty","christmas","tattoo","fans","makeup","boats","yachts","motorcycles","dance","date","racing","win","faith","download","accountant","stream","gdn","mom","pro","lol","pics","photo"];

    var SLD_SUFFIXES = ["co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.in","firm.in","com.br","co.jp","ne.jp","com.cn","com.tw","co.kr","com.mx","co.za","com.sg","com.hk","co.nz","com.pl","com.tr","co.id","com.my","com.ph","com.vn","com.ar","com.co","com.pe","gob.mx","com.ng","co.ke"];

    var KEYWORDS = ["login","signin","sign-in","verify","verification","secure","account","update","confirm","billing","wallet","seed-phrase","recovery","restore","claim","prize","gift","bonus","airdrop","refund","suspended","unlock","password","banking","invoice","validate","authenticate","webscr","ebayisapi"];

    var REDIRECT_PARAMS = ["url","next","redirect","redirect_uri","redirect_url","return","returnurl","return_url","continue","dest","destination","target","goto","link","out","r","u","forward"];

    function levenshtein(a, b) {
      var m = a.length, n = b.length, i, j;
      if (!m) return n; if (!n) return m;
      var prev = [], cur = [];
      for (j = 0; j <= n; j++) prev[j] = j;
      for (i = 1; i <= m; i++) {
        cur[0] = i;
        for (j = 1; j <= n; j++) {
          cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        }
        var t = prev; prev = cur; cur = t;
      }
      return prev[n];
    }

    function normalizeLabel(s) {
      return s.toLowerCase()
        .replace(/0/g, "o").replace(/1/g, "l").replace(/!/g, "l")
        .replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s")
        .replace(/7/g, "t").replace(/@/g, "a").replace(/\$/g, "s")
        .replace(/rn/g, "m").replace(/vv/g, "w")
        .replace(/-/g, "");
    }

    function registrableDomain(host) {
      var labels = host.split(".").filter(Boolean);
      if (labels.length <= 2) return { reg: host, sub: [], tld: labels[labels.length - 1] || "", regLabel: labels[0] || "" };
      var last2 = labels.slice(-2).join(".");
      var take = SLD_SUFFIXES.indexOf(last2) >= 0 ? 3 : 2;
      var regLabels = labels.slice(-take);
      return {
        reg: regLabels.join("."),
        sub: labels.slice(0, labels.length - take),
        tld: labels[labels.length - 1],
        regLabel: regLabels[0]
      };
    }

    function isIpHost(host) {
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
      if (/^0x[0-9a-f]+$/i.test(host)) return true;
      if (/^\d+$/.test(host)) return true;
      if (host.indexOf(":") >= 0) return true; /* IPv6 literal (brackets stripped by URL) */
      return false;
    }

    function chk(level, title, detail, points) {
      return { level: level, title: title, detail: detail, points: points || 0 };
    }

    function bandFor(risk) {
      if (risk >= 70) return { key: "dangerous", label: "Dangerous", advice: "Do not open this. Nothing about it needs your password, card, or wallet — and a real service would never reach you through a code like this. If it's on a sticker in public, tell the venue." };
      if (risk >= 45) return { key: "suspicious", label: "Suspicious", advice: "Treat this as hostile until proven otherwise. Don't sign in, pay, or download anything. If you need the service, open its app or type its address yourself." };
      if (risk >= 20) return { key: "caution", label: "Caution", advice: "Some checks raised questions. Read the destination domain character by character, and don't enter credentials or payment details unless it's exactly the domain you expected." };
      return { key: "low", label: "Low risk", advice: "No red flags found in the structure of this code. Still glance at the domain before signing in anywhere — a clean structure isn't proof of who's behind it." };
    }

    function analyze(rawInput) {
      var raw = String(rawInput || "").trim();
      var res = {
        raw: raw, kind: "text", kindLabel: "Plain text", url: null, host: null,
        checks: [], risk: 0, brandClaim: null, anatomy: null, meta: {}
      };
      if (!raw) { res.checks.push(chk("warn", "Empty content", "The code decoded to nothing readable.", 10)); return finish(res); }

      var lower = raw.toLowerCase();

      /* ---- Wi-Fi ---- */
      if (/^wifi:/i.test(raw)) {
        res.kind = "wifi"; res.kindLabel = "Wi-Fi join code";
        var fields = {};
        /* fields split on unescaped ";", key/value on unescaped ":", and \x escapes are removed */
        var unesc = function (s) { return s.replace(/\\(.)/g, "$1"); };
        (raw.slice(5).match(/(?:\\.|[^;\\])+/g) || []).forEach(function (part) {
          var kv = part.match(/^((?:\\.|[^:\\])+):((?:.|\n)*)$/);
          if (kv) fields[unesc(kv[1]).toUpperCase()] = unesc(kv[2]);
        });
        res.meta.ssid = fields.S || "(hidden name)";
        var sec = (fields.T || "nopass").toUpperCase();
        res.checks.push(chk("warn", "Scanning auto-joins a network", "This code connects your phone to “" + res.meta.ssid + "” (" + sec + ") without typing anything. A rogue hotspot with a familiar name can sit between you and everything you do on it.", 15));
        if (sec === "NOPASS" || sec === "NONE" || sec === "") {
          res.checks.push(chk("bad", "Open network — no encryption", "Anyone nearby can watch unencrypted traffic on an open network. Avoid banking or email sign-in while connected.", 30));
        } else if (sec === "WEP") {
          res.checks.push(chk("bad", "WEP security", "WEP was broken years ago and offers almost no protection.", 25));
        } else {
          res.checks.push(chk("ok", "Network uses " + sec, "That's a current Wi-Fi security standard. It doesn't prove the network belongs to who you think it does.", 0));
        }
        if (String(fields.H).toLowerCase() === "true") {
          res.checks.push(chk("warn", "Hidden network", "The network doesn't broadcast its name, so you can't compare it against a posted sign.", 8));
        }
        res.checks.push(chk("ok", "Tip: forget it afterwards", "If you join, remove the network from your saved list later so your phone doesn't auto-reconnect to a same-named hotspot elsewhere.", 0));
        return finish(res);
      }

      /* ---- Authenticator ---- */
      if (/^otpauth:/i.test(raw)) {
        res.kind = "otp"; res.kindLabel = "Authenticator setup code";
        var issuer = "";
        var m = raw.match(/otpauth:\/\/(?:totp|hotp)\/([^?]*)/i);
        if (m) { try { issuer = decodeURIComponent(m[1]); } catch (e) { issuer = m[1]; } }
        res.meta.issuer = issuer;
        res.checks.push(chk("bad", "This is a two-factor seed", "Scanning it adds an account to your authenticator app and starts generating its login codes. Only ever scan one of these on the real service's own screen, while you are signed in and setting up 2FA yourself.", 45));
        res.checks.push(chk("warn", "Never scan one from a poster, email, or stranger", "A code handed to you can enroll you in someone else's account — or be the step that hands them yours.", 15));
        return finish(res);
      }

      /* ---- vCard ---- */
      if (/^begin:vcard/i.test(raw)) {
        res.kind = "vcard"; res.kindLabel = "Contact card";
        var nm = raw.match(/\nFN[^:]*:(.+)/i);
        res.meta.name = nm ? nm[1].trim() : "";
        res.checks.push(chk("warn", "Adds a contact to your phone", "A saved contact can make a later scam call or text look trusted — your phone will show the name the attacker chose, not a number you verified.", 18));
        if (res.meta.name) res.checks.push(chk("ok", "Name on the card: " + res.meta.name, "Ask whether that's a name you were expecting to add.", 0));
        return finish(res);
      }

      /* ---- tel / sms / mailto / geo ---- */
      if (/^(tel:|sms:|smsto:)/i.test(raw)) {
        res.kind = "message"; res.kindLabel = /^sms/i.test(raw) ? "Text message code" : "Phone call code";
        var num = raw.replace(/^(tel:|sms:|smsto:)/i, "").split(/[;?]/)[0];
        res.meta.number = num;
        res.checks.push(chk("warn", "Opens a call or message to " + num, "Premium-rate and overseas numbers can charge by the minute, and a pre-written text can sign you up for paid services. Check the number against the one printed on the business's own site or card.", 18));
        return finish(res);
      }
      if (/^mailto:/i.test(raw)) {
        res.kind = "message"; res.kindLabel = "Email code";
        res.checks.push(chk("warn", "Opens a pre-addressed email", "Check the address carefully — a lookalike domain here is the same trick as a lookalike website.", 10));
        return finish(res);
      }
      if (/^geo:/i.test(raw)) {
        res.kind = "geo"; res.kindLabel = "Location pin";
        res.checks.push(chk("ok", "Just map coordinates", "No link to open. Still confirm the destination is where you actually mean to go.", 2));
        return finish(res);
      }

      /* ---- Payment addresses ---- */
      if (/^(bitcoin:|ethereum:|litecoin:|dogecoin:|upi:\/\/|cashapp:|solana:)/i.test(raw) || /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(raw) || /^0x[a-fA-F0-9]{40}$/.test(raw)) {
        res.kind = "payment"; res.kindLabel = "Payment code";
        res.checks.push(chk("bad", "Pre-filled payment destination", "This code opens a wallet or payment app with the receiving address already set. Crypto and UPI transfers are effectively irreversible — if the address was swapped or the code is a sticker over the real one, the money is gone.", 35));
        res.checks.push(chk("warn", "Verify the address out loud", "Compare the first and last characters against an address the payee gives you through a channel you already trust.", 10));
        return finish(res);
      }

      /* ---- URL-ish? ---- */
      var urlText = raw;
      /* "localhost:8080" or "10.0.0.5:8080/x" looks like scheme:, but it's host:port */
      var hostPort = /^[a-z0-9.-]+:\d+([\/?#]|$)/i.test(raw);
      var hasScheme = !hostPort && /^[a-z][a-z0-9+.-]*:/i.test(raw);
      if (hostPort) {
        urlText = "https://" + raw;
        hasScheme = true;
        res.meta.schemeAdded = true;
      } else if (!hasScheme && /^[^\s]+\.[a-z]{2,}(\/\S*)?$/i.test(raw) && raw.indexOf(" ") < 0) {
        urlText = "https://" + raw;
        hasScheme = true;
        res.meta.schemeAdded = true;
      }
      var parsed = null;
      if (hasScheme) { try { parsed = new URL(urlText); } catch (e) { parsed = null; } }

      if (!parsed) {
        res.checks.push(chk("ok", "No link inside", "This code carries plain text only — nothing opens and nothing downloads. Read it like you'd read a note left by a stranger.", 3));
        return finish(res);
      }

      /* ---- URL analysis ---- */
      res.kind = "url"; res.kindLabel = "Web link";
      res.url = parsed;
      var scheme = parsed.protocol.replace(":", "").toLowerCase();
      var host = parsed.hostname.toLowerCase();
      res.host = host;
      var parts = registrableDomain(host);
      res.anatomy = { scheme: scheme, sub: parts.sub, reg: parts.reg, regLabel: parts.regLabel, tld: parts.tld, path: parsed.pathname, query: parsed.search };
      var pathAndQuery = (parsed.pathname + "?" + (parsed.search || "")).toLowerCase();

      /* Scheme */
      if (scheme === "https") {
        res.checks.push(chk("ok", "Encrypted connection (HTTPS)", "The padlock only means the connection is encrypted — it says nothing about who runs the site. Phishing sites have valid HTTPS too.", 0));
      } else if (scheme === "http") {
        res.checks.push(chk("bad", "Unencrypted HTTP", "Anything you type — passwords included — travels in plain text, and the page can be altered in transit. Legitimate login and payment pages don't use HTTP.", 22));
      } else if (["javascript", "data", "file", "vbscript", "blob"].indexOf(scheme) >= 0) {
        res.checks.push(chk("bad", "Dangerous scheme: " + scheme + ":", "This isn't a website at all — it's code or a local file reference dressed as a link. Never open it.", 70));
      } else {
        res.checks.push(chk("warn", "Opens an app, not a website (" + scheme + ":)", "App links can jump straight into a banking, wallet, or settings screen. Check which app it wakes up before confirming anything.", 25));
      }

      /* Host form */
      var isIp = isIpHost(host);
      if (isIp) {
        res.checks.push(chk("bad", "Raw IP address instead of a domain", "Real services use domain names so they can prove who they are with a certificate. An IP address gives you no identity to check.", 35));
      }
      if (host.split(".").some(function (l) { return l.indexOf("xn--") === 0; })) {
        res.checks.push(chk("bad", "Punycode domain (xn--…)", "This encodes lookalike characters from other alphabets. Rendered in some apps, it can look identical to a famous brand while being a completely different site.", 30));
      }
      if (parsed.username || parsed.password) {
        res.checks.push(chk("bad", "The @ trick — fake address up front", "Everything before the @ is ignored by the browser. This link actually goes to " + host + ", not to the name written before the @.", 35));
      }
      if (parsed.port && !(scheme === "https" && parsed.port === "443") && !(scheme === "http" && parsed.port === "80")) {
        res.checks.push(chk("warn", "Unusual port (" + parsed.port + ")", "Real public services sit on the standard port. A custom port often means a throwaway server.", 10));
      }

      /* Subdomain depth */
      if (parts.sub.length >= 4) {
        res.checks.push(chk("bad", parts.sub.length + " layers of subdomains", "Deep subdomain stacks are a classic costume: the eye stops at the familiar name on the left and never reaches the real domain on the right.", 22));
      } else if (parts.sub.length === 3) {
        res.checks.push(chk("warn", "3 layers of subdomains", "More layers than most real services use. Read the part immediately before ." + parts.tld + " — that's who you're actually visiting.", 12));
      } else if (!isIp) {
        res.checks.push(chk("ok", "Normal domain structure", parts.sub.length ? "Subdomain: " + parts.sub.join(".") + " · Real domain: " + parts.reg : "Real domain: " + parts.reg, 0));
      }

      /* Shortener */
      if (SHORTENERS.indexOf(parts.reg) >= 0 || SHORTENERS.indexOf(host) >= 0) {
        res.checks.push(chk("warn", "URL shortener — destination hidden", parts.reg + " redirects to somewhere you can't see from the code, and the target can be changed after printing. A scanner can flag it but can't see through it without visiting — so don't let curiosity do the visiting on a device with your accounts on it.", 25));
      }

      /* Suspicious TLD */
      if (SUS_TLDS.indexOf(parts.tld) >= 0) {
        res.checks.push(chk("warn", "High-abuse domain ending (." + parts.tld + ")", "Cheap, disposable endings are where phishing kits live because domains cost pennies and burn fast. Not proof of a scam — but real banks and airlines rarely use them.", 14));
      }

      /* Brand impersonation */
      var hostLabels = host.split(".");
      var brandHit = null, brandOfficial = null;
      BRANDS.forEach(function (b) {
        var official = b.domains.indexOf(parts.reg) >= 0 || b.domains.some(function (d) { return host === d || host.endsWith("." + d); });
        if (official) brandOfficial = b;
      });
      if (!brandOfficial && !isIp) {
        BRANDS.forEach(function (b) {
          if (brandHit) return;
          b.keys.forEach(function (key) {
            if (brandHit) return;
            /* brand name sitting in a subdomain */
            /* substring matches only for long keys: "ups" must not hit "groups", "live" must not hit "olive" */
            var long = key.length >= 5;
            var subHit = parts.sub.some(function (l) { return normalizeLabel(l) === key || (long && l.toLowerCase().indexOf(key) >= 0); });
            if (subHit) { brandHit = { brand: b, how: "subdomain" }; return; }
            /* brand inside the registrable label */
            var regNorm = normalizeLabel(parts.regLabel);
            if (regNorm === key) { brandHit = { brand: b, how: "lookalike" }; return; }
            if (long && regNorm.indexOf(key) >= 0 && regNorm.length > key.length) { brandHit = { brand: b, how: "embedded" }; return; }
            /* typosquat distance */
            var d = levenshtein(regNorm, key);
            if (d >= 1 && d <= 2 && key.length >= 4) { brandHit = { brand: b, how: "typosquat", dist: d }; return; }
            hostLabels.forEach(function (l) {
              if (brandHit) return;
              var ln = normalizeLabel(l);
              if (l.toLowerCase() !== key && ln === key) brandHit = { brand: b, how: "lookalike" };
              else if (ln !== key && levenshtein(ln, key) >= 1 && levenshtein(ln, key) <= 1 && key.length >= 5 && l.length >= 4) brandHit = { brand: b, how: "typosquat", dist: 1 };
            });
          });
        });
        /* brand name in the path of an unrelated domain */
        if (!brandHit) {
          BRANDS.forEach(function (b) {
            if (brandHit) return;
            b.keys.forEach(function (key) {
              if (brandHit) return;
              if (key.length >= 5 && pathAndQuery.indexOf(key) >= 0) brandHit = { brand: b, how: "path" };
            });
          });
        }
      }
      if (brandOfficial) {
        res.checks.push(chk("ok", "Domain really is " + brandOfficial.name, parts.reg + " is an official " + brandOfficial.name + " domain. (Still check the path makes sense — real domains get abused in ads and open redirects too.)", 0));
      } else if (brandHit) {
        res.brandClaim = brandHit.brand.name;
        if (brandHit.how === "subdomain") {
          res.checks.push(chk("bad", "Dressed up as " + brandHit.brand.name + " — it isn't", "“" + brandHit.brand.name + "” appears only as a subdomain. The real destination is " + parts.reg + ", which is not a " + brandHit.brand.name + " domain (" + brandHit.brand.domains.join(", ") + ").", 45));
        } else if (brandHit.how === "typosquat") {
          res.checks.push(chk("bad", "Typosquat of " + brandHit.brand.name, parts.regLabel + " is " + (brandHit.dist || 1) + " character edit away from “" + brandHit.brand.keys[0] + "”. One swapped, dropped, or lookalike character — exactly how fake login pages are spelled.", 42));
        } else if (brandHit.how === "embedded") {
          res.checks.push(chk("bad", "Brand name embedded in a stranger's domain", parts.reg + " contains “" + brandHit.brand.keys[0] + "” but is not " + brandHit.brand.name + " (" + brandHit.brand.domains.join(", ") + "). Real brands don't need extra words welded onto their name.", 40));
        } else if (brandHit.how === "path") {
          res.checks.push(chk("warn", "Brand name in the page path, not the domain", "The address mentions " + brandHit.brand.name + " in its path, but the site itself is " + parts.reg + ". Paths are free text — anyone can write any brand name there.", 25));
        } else {
          res.checks.push(chk("bad", "Lookalike of " + brandHit.brand.name, "Swap-in characters (0 for o, 1 for l, rn for m) make this read as " + brandHit.brand.name + " at a glance. The real domain is " + parts.reg + ".", 42));
        }
      }

      /* Hyphens & digits in the real domain label */
      var hyphens = (parts.regLabel.match(/-/g) || []).length;
      if (hyphens >= 3) res.checks.push(chk("warn", "Hyphen-stuffed domain", parts.regLabel + " stacks " + hyphens + " hyphens — a common way to weld “secure-login-verify” onto a throwaway name.", 10));
      else if (hyphens === 2) res.checks.push(chk("warn", "Two hyphens in the domain name", "Worth a second look — legitimate brands keep their domains short and clean.", 5));
      var digits = (parts.regLabel.match(/\d/g) || []).length;
      if (digits >= 3) res.checks.push(chk("warn", "Digit-heavy domain name", digits + " digits in “" + parts.regLabel + "” — mass-registered phishing domains lean on numbers.", 6));

      /* Length & encoding */
      if (raw.length > 200) res.checks.push(chk("warn", "Very long link (" + raw.length + " characters)", "Length buries the destination. The longer the link, the less of it anyone actually reads.", 12));
      else if (raw.length > 100) res.checks.push(chk("warn", "Long link (" + raw.length + " characters)", "Long enough that the important part — the domain — scrolls out of view in most previews.", 6));
      var encCount = (raw.match(/%[0-9a-fA-F]{2}/g) || []).length;
      if (encCount >= 4) res.checks.push(chk("warn", "Heavy percent-encoding", encCount + " encoded characters hide what the address really says — including, sometimes, a second hidden address.", 12));
      else if (encCount >= 1 && /%2e|%252e|%2f/i.test(raw)) res.checks.push(chk("warn", "Encoded dots or slashes", "Encoding a “.” or “/” is a way to smuggle a different address past a quick glance.", 10));

      /* Second address hiding inside */
      if (parsed.pathname.indexOf("://") >= 0 || /[?&](https?%3a|https?:)/i.test(raw)) {
        res.checks.push(chk("warn", "A second web address is hiding in this one", "The path or parameters contain another URL — a classic open-redirect costume that borrows the first domain's trust.", 18));
      } else {
        var rpHit = null;
        parsed.searchParams.forEach(function (v, k) {
          if (!rpHit && REDIRECT_PARAMS.indexOf(k.toLowerCase()) >= 0 && /^https?:\/\//i.test(v)) rpHit = k;
        });
        if (rpHit) res.checks.push(chk("warn", "Redirect parameter (“" + rpHit + "=…”) points elsewhere", "The first domain may be genuine, but it hands you off to an outside address. Where you land is what counts.", 15));
      }

      /* Pressure keywords */
      var kwHits = KEYWORDS.filter(function (k) { return pathAndQuery.indexOf(k) >= 0 || host.indexOf(k) >= 0; });
      if (kwHits.length >= 3) {
        res.checks.push(chk("warn", "Stacked urgency words: " + kwHits.slice(0, 4).join(", "), "Phishing pages lean on verify / suspended / claim language to rush you past the part where you'd check the domain.", 14));
      } else if (kwHits.length >= 1) {
        res.checks.push(chk("warn", "Asks you to " + kwHits[0].replace("-", " "), "On its own that's normal — combined with any other flag here, it's the hook. Real services rarely start this conversation from a sticker.", 7));
      }

      if (res.meta.schemeAdded) {
        res.checks.push(chk("ok", "No scheme in the code — read as HTTPS", "The code contained a bare domain, so it was treated as an https:// link for this check.", 0));
      }
      return finish(res);
    }

    function finish(res) {
      var total = 0;
      res.checks.forEach(function (c) { total += c.points; });
      res.risk = Math.max(0, Math.min(100, total));
      res.band = bandFor(res.risk);
      var order = { bad: 0, warn: 1, ok: 2 };
      res.checks.sort(function (a, b) { return order[a.level] - order[b.level]; });
      return res;
    }
"use strict";
    /* ================= UI ================= */
    function $(id) { return document.getElementById(id); }
    function esc(s) {
      return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      });
    }
    var ICONS = {
      ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>',
      warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
      bad: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
      copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
      ext: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>'
    };

    var scanHistory = [];
    var currentResult = null;
    var pendingOpenUrl = null;

    function toast(msg) {
      var t = $("toast");
      t.textContent = msg;
      t.classList.add("show");
      clearTimeout(toast._timer);
      toast._timer = setTimeout(function () { t.classList.remove("show"); }, 2400);
    }

    function beep() {
      try {
        var AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return;
        if (!beep._ctx) beep._ctx = new AC();
        var ctx = beep._ctx;
        if (ctx.state === "suspended") ctx.resume();
        var o = ctx.createOscillator(), g = ctx.createGain();
        o.type = "sine"; o.frequency.value = 920;
        g.gain.setValueAtTime(0.12, ctx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.14);
        o.connect(g); g.connect(ctx.destination);
        o.start(); o.stop(ctx.currentTime + 0.15);
      } catch (e) { /* audio is a nicety, not a requirement */ }
      if (navigator.vibrate) { try { navigator.vibrate(50); } catch (e) {} }
    }

    function gaugeColor(bandKey) {
      if (bandKey === "low") return "var(--good)";
      if (bandKey === "dangerous") return "var(--bad)";
      return "var(--warn)";
    }

    function runAnalysis(raw, sourceLabel) {
      var res = analyze(raw);
      currentResult = res;
      renderResult(res);
      scanHistory.unshift({ raw: res.raw, risk: res.risk, band: res.band, kindLabel: res.kindLabel, host: res.host, when: new Date() });
      if (scanHistory.length > 12) scanHistory.length = 12;
      renderHistory();
      beep();
      var el = $("result-h");
      if (el && el.scrollIntoView) {
        var rect = el.getBoundingClientRect();
        if (rect.top < 0 || rect.top > window.innerHeight * 0.6) el.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      return res;
    }

    function renderResult(res) {
      var band = res.band;
      var html = "";
      html += '<div class="verdict-row">';
      html += '<div class="gauge"><svg viewBox="0 0 200 118" role="img" aria-label="Risk score ' + res.risk + ' out of 100">';
      html += '<path d="M 20 108 A 82 82 0 0 1 180 108" fill="none" stroke="var(--line)" stroke-width="15" stroke-linecap="round" pathLength="100" stroke-dasharray="100 100"/>';
      html += '<path id="gaugeArc" d="M 20 108 A 82 82 0 0 1 180 108" fill="none" stroke="' + gaugeColor(band.key) + '" stroke-width="15" stroke-linecap="round" pathLength="100" stroke-dasharray="0 100" style="transition: stroke-dasharray .8s ease"/>';
      html += '</svg><div class="g-num" id="gaugeNum">0</div><div class="g-cap">Risk score / 100</div></div>';
      html += '<div class="verdict-main"><span class="pill ' + band.key + '"><span class="dot"></span>' + esc(band.label) + '</span>';
      html += '<p>' + esc(band.advice) + '</p>';
      html += '<div class="type-line">Code type: <strong>' + esc(res.kindLabel) + '</strong>';
      if (res.host) html += ' · Destination: <strong class="mono">' + esc(res.host) + '</strong>';
      html += '</div></div></div>';

      if (res.brandClaim && res.anatomy) {
        html += '<div class="impostor" role="note"><div class="row"><span class="k">Made to look like</span><span><b>' + esc(res.brandClaim) + '</b></span></div>';
        html += '<div class="row"><span class="k">Actually goes to</span><span class="mono"><b class="bad">' + esc(res.anatomy.reg) + '</b></span></div></div>';
      }

      html += '<div class="decoded"><div class="decoded-head"><span>Decoded content</span>';
      html += '<button class="icon-btn" id="btnCopy">' + ICONS.copy + 'Copy</button></div>';
      html += '<div class="decoded-body mono">' + esc(res.raw) + '</div></div>';

      if (res.anatomy) {
        var a = res.anatomy;
        html += '<div class="anatomy"><h3>Address anatomy — the bold part is who you\'re really dealing with</h3><div class="anatomy-flow">';
        html += '<span class="seg-part mono"><small>Scheme</small>' + esc(a.scheme) + '://</span>';
        if (a.sub.length) html += '<span class="seg-part mono' + (res.brandClaim ? " flagged" : "") + '"><small>Subdomain (costume)</small>' + esc(a.sub.join(".")) + '.</span>';
        html += '<span class="seg-part mono core"><small>Real domain</small>' + esc(a.reg) + '</span>';
        if (a.path && a.path !== "/") html += '<span class="seg-part mono"><small>Path</small>' + esc(a.path) + '</span>';
        else html += '<span class="seg-part mono"><small>Path</small>/</span>';
        if (a.query) html += '<span class="seg-part mono"><small>Query</small>' + esc(a.query) + '</span>';
        html += '</div></div>';
      }

      html += '<div class="checks"><h3>Check by check</h3>';
      res.checks.forEach(function (c) {
        html += '<div class="check ' + c.level + '"><span class="ic">' + (c.level === "ok" ? ICONS.ok : c.level === "warn" ? ICONS.warn : ICONS.bad) + '</span>';
        html += '<span><span class="t">' + esc(c.title) + '</span><div class="d">' + esc(c.detail) + '</div></span>';
        html += '<span class="pts">' + (c.points > 0 ? "+" + c.points : "—") + '</span></div>';
      });
      html += '</div>';

      html += '<div class="result-actions">';
      if (res.kind === "url" && res.url && ["http:", "https:"].indexOf(res.url.protocol) >= 0) {
        html += '<button class="btn ' + (band.key === "low" ? "btn-primary" : "btn-danger") + '" id="btnOpen">' + ICONS.ext + (band.key === "low" ? "Open link" : "Open link anyway") + '</button>';
      }
      html += '<button class="btn btn-ghost" id="btnRescan">Scan another</button>';
      html += '</div>';
      html += '<p class="fineprint">Points add up to the risk score. A single strong signal — a lookalike domain, the @ trick, a dangerous scheme — is enough on its own to stay away.</p>';

      $("resultBody").innerHTML = html;

      /* animate gauge */
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          var arc = $("gaugeArc");
          if (arc) arc.setAttribute("stroke-dasharray", res.risk + " 100");
          var num = $("gaugeNum"), start = null;
          function step(ts) {
            if (!num) return;
            if (!start) start = ts;
            var p = Math.min(1, (ts - start) / 700);
            num.textContent = Math.round(res.risk * p);
            if (p < 1) requestAnimationFrame(step);
          }
          if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
            if (num) num.textContent = res.risk;
          } else {
            requestAnimationFrame(step);
          }
        });
      });

      $("btnCopy").addEventListener("click", function () {
        copyText(res.raw);
      });
      var openBtn = $("btnOpen");
      if (openBtn) openBtn.addEventListener("click", function () { requestOpen(res); });
      $("btnRescan").addEventListener("click", function () {
        window.scrollTo({ top: 0, behavior: "smooth" });
        var inp = $("pasteInput");
        if (inp) inp.value = "";
      });
    }

    function copyText(text) {
      function done() { toast("Copied to clipboard"); }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallback(); });
      } else fallback();
      function fallback() {
        var ta = document.createElement("textarea");
        ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta); ta.select();
        try { document.execCommand("copy"); done(); } catch (e) { toast("Copy failed — long-press the text instead"); }
        document.body.removeChild(ta);
      }
    }

    function requestOpen(res) {
      if (!res.url) return;
      var url = res.url.href;
      if (res.band.key === "low") {
        window.open(url, "_blank", "noopener");
        return;
      }
      pendingOpenUrl = url;
      $("modalTitle").textContent = res.band.key === "dangerous" ? "This scored " + res.risk + "/100 — really open it?" : "This scored " + res.risk + "/100";
      $("modalText").textContent = res.band.key === "dangerous"
        ? "The checks found strong signs of a phishing link. Opening it on the device where your email and banking live is exactly what the code is counting on. If you must inspect it, use a spare device with no accounts signed in."
        : "Some checks raised questions about this link. If you open it, don't sign in or pay anything unless the domain in your address bar is exactly the one you expected.";
      $("modalUrl").textContent = url;
      $("overlay").classList.add("open");
    }
    $("modalCancel").addEventListener("click", function () { $("overlay").classList.remove("open"); pendingOpenUrl = null; });
    $("overlay").addEventListener("click", function (e) { if (e.target === $("overlay")) { $("overlay").classList.remove("open"); pendingOpenUrl = null; } });
    $("modalOpen").addEventListener("click", function () {
      $("overlay").classList.remove("open");
      if (pendingOpenUrl) window.open(pendingOpenUrl, "_blank", "noopener");
      pendingOpenUrl = null;
    });

    function renderHistory() {
      var list = $("histList"), empty = $("histEmpty");
      if (!scanHistory.length) { list.innerHTML = ""; empty.style.display = ""; return; }
      empty.style.display = "none";
      list.innerHTML = scanHistory.map(function (h, i) {
        var title = h.host || h.raw;
        var time = h.when.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
        return '<li><button class="hist-item" data-idx="' + i + '">'
          + '<span class="hist-score ' + h.band.key + '">' + h.risk + '</span>'
          + '<span class="h-main"><span class="h-url mono">' + esc(title) + '</span>'
          + '<span class="h-meta" style="display:block;">' + esc(h.kindLabel) + ' · ' + esc(time) + '</span></span>'
          + '<span class="h-verdict ' + h.band.key + '">' + esc(h.band.label) + '</span></button></li>';
      }).join("");
      Array.prototype.forEach.call(list.querySelectorAll(".hist-item"), function (btn) {
        btn.addEventListener("click", function () {
          var h = scanHistory[Number(btn.getAttribute("data-idx"))];
          if (h) { currentResult = analyze(h.raw); renderResult(currentResult); window.scrollTo({ top: 0, behavior: "smooth" }); setTimeout(function () { var el = $("result-h"); if (el) el.scrollIntoView({ behavior: "smooth" }); }, 60); }
        });
      });
    }

    /* ================= Tabs ================= */
    var tabs = Array.prototype.slice.call(document.querySelectorAll(".seg [role=tab]"));
    function selectTab(tab) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", on ? "true" : "false");
        $(t.getAttribute("data-pane")).hidden = !on;
      });
      if (tab.getAttribute("data-pane") !== "pane-camera") stopCamera();
    }
    tabs.forEach(function (t) { t.addEventListener("click", function () { selectTab(t); }); });

    /* ================= Camera ================= */
    var stream = null, scanning = false, rafId = null;
    var video = $("camVideo"), stage = $("stage");
    var scanCanvas = document.createElement("canvas");
    var scanCtx = scanCanvas.getContext("2d", { willReadFrequently: true });

    function camError(msg) {
      var e = $("camErr");
      e.textContent = msg;
      e.classList.add("show");
    }
    function clearCamError() { $("camErr").classList.remove("show"); }

    function startCamera() {
      if (stream) return; /* second click would orphan the first stream */
      clearCamError();
      if (typeof jsQR === "undefined") {
        camError("The QR decoder library didn't load — check your connection, or use the Upload or Paste link tabs instead.");
        return;
      }
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        camError("This browser can't open a camera here. Use the Upload tab with a photo of the code instead.");
        return;
      }
      navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false })
        .then(function (s) {
          stream = s;
          video.srcObject = s;
          return video.play();
        })
        .then(function () {
          stage.classList.add("live");
          $("btnCamStart").disabled = true;
          $("btnCamStop").disabled = false;
          scanning = true;
          tick();
        })
        .catch(function (err) {
          if (err && (err.name === "NotAllowedError" || err.name === "SecurityError")) {
            camError("Camera permission was denied. Allow camera access in your browser settings, or use the Upload tab instead.");
          } else if (err && err.name === "NotFoundError") {
            camError("No camera found on this device. Use the Upload tab instead.");
          } else {
            camError("The camera couldn't start (" + (err && err.name ? err.name : "unknown error") + "). The Upload tab works just as well.");
          }
        });
    }

    var lastTick = 0;
    function tick() {
      if (!scanning) return;
      rafId = requestAnimationFrame(tick);
      var now = performance.now();
      if (now - lastTick < 120) return;
      lastTick = now;
      if (video.readyState !== video.HAVE_ENOUGH_DATA) return;
      var w = video.videoWidth, h = video.videoHeight;
      if (!w || !h) return;
      var scale = Math.min(1, 900 / Math.max(w, h));
      scanCanvas.width = Math.round(w * scale);
      scanCanvas.height = Math.round(h * scale);
      scanCtx.drawImage(video, 0, 0, scanCanvas.width, scanCanvas.height);
      var img;
      try { img = scanCtx.getImageData(0, 0, scanCanvas.width, scanCanvas.height); } catch (e) { return; }
      var code = null;
      try { code = jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" }); } catch (e) { code = null; }
      if (code && code.data) {
        var data = code.data;
        stopCamera();
        runAnalysis(data, "camera");
      }
    }

    function stopCamera() {
      scanning = false;
      if (rafId) cancelAnimationFrame(rafId);
      rafId = null;
      if (stream) { stream.getTracks().forEach(function (t) { t.stop(); }); stream = null; }
      video.srcObject = null;
      stage.classList.remove("live");
      $("btnCamStart").disabled = false;
      $("btnCamStop").disabled = true;
    }
    $("btnCamStart").addEventListener("click", startCamera);
    $("btnCamStop").addEventListener("click", stopCamera);
    document.addEventListener("visibilitychange", function () { if (document.hidden) stopCamera(); });

    /* ================= Upload ================= */
    var fileInput = $("fileInput"), dropZone = $("dropZone");
    $("btnPickFile").addEventListener("click", function () { fileInput.click(); });
    fileInput.addEventListener("change", function () {
      if (fileInput.files && fileInput.files[0]) decodeImageFile(fileInput.files[0]);
      fileInput.value = "";
    });
    ["dragenter", "dragover"].forEach(function (ev) {
      dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.add("over"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.remove("over"); });
    });
    dropZone.addEventListener("drop", function (e) {
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) decodeImageFile(f);
    });

    function uploadError(msg) {
      var e = $("uploadErr");
      e.textContent = msg;
      e.classList.add("show");
    }
    function decodeImageFile(file) {
      $("uploadErr").classList.remove("show");
      if (typeof jsQR === "undefined") { uploadError("The QR decoder library didn't load — check your connection and reload, or paste the link instead."); return; }
      if (!/^image\//.test(file.type) && !/\.(png|jpe?g|gif|webp|bmp)$/i.test(file.name)) {
        uploadError("That doesn't look like an image file. Screenshots (PNG) and photos (JPG) work best.");
        return;
      }
      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = function () {
        URL.revokeObjectURL(url);
        var maxSide = 2200;
        var scale = Math.min(1, maxSide / Math.max(img.naturalWidth, img.naturalHeight));
        var c = document.createElement("canvas");
        c.width = Math.round(img.naturalWidth * scale);
        c.height = Math.round(img.naturalHeight * scale);
        var ctx = c.getContext("2d", { willReadFrequently: true });
        ctx.drawImage(img, 0, 0, c.width, c.height);
        var data;
        try { data = ctx.getImageData(0, 0, c.width, c.height); } catch (e) { uploadError("Couldn't read that image. Try a screenshot instead of a photo of a screen."); return; }
        var code = null;
        try { code = jsQR(data.data, data.width, data.height, { inversionAttempts: "attemptBoth" }); } catch (e) { code = null; }
        if (code && code.data) runAnalysis(code.data, "upload");
        else uploadError("No QR code found in that image. Try a tighter crop, better light, or a straight-on screenshot.");
      };
      img.onerror = function () { URL.revokeObjectURL(url); uploadError("That image couldn't be opened. Try PNG or JPG."); };
      img.src = url;
    }

    /* ================= Paste ================= */
    $("btnAnalyze").addEventListener("click", function () {
      var v = $("pasteInput").value.trim();
      var e = $("pasteErr");
      if (!v) {
        e.textContent = "Paste a link or decoded QR text first.";
        e.classList.add("show");
        return;
      }
      e.classList.remove("show");
      runAnalysis(v, "paste");
    });
    $("btnClipboard").addEventListener("click", function () {
      if (navigator.clipboard && navigator.clipboard.readText) {
        navigator.clipboard.readText().then(function (t) {
          if (t) { $("pasteInput").value = t; $("pasteErr").classList.remove("show"); }
          else toast("Clipboard is empty");
        }, function () { toast("Clipboard access was blocked — paste manually"); });
      } else {
        toast("Clipboard reading isn't available here — paste manually");
      }
    });

    /* ================= Samples ================= */
    var SAMPLES = [
      { label: "A real article link", url: "https://en.wikipedia.org/wiki/QR_code", dot: "var(--good)", qr: true, cap: "What a clean code looks like" },
      { label: "Subdomain costume", url: "https://paypal.com.login-verify.example/signin", dot: "var(--bad)", qr: true, cap: "“PayPal” is just a subdomain here" },
      { label: "One-letter-off typosquat", url: "https://paypa1.example/account/verify", dot: "var(--bad)", qr: true, cap: "That's a 1, not an l" },
      { label: "Shortener blindfold", url: "https://bit.ly/claim-your-prize", dot: "var(--warn)", qr: false, cap: "Destination completely hidden" },
      { label: "Fake Wi-Fi login page", url: "http://192.168.4.21/free-wifi-login", dot: "var(--bad)", qr: false, cap: "Raw IP + unencrypted HTTP" },
      { label: "Airport Wi-Fi code", url: "WIFI:T:WPA;S:CLT-Free-WiFi;P:flyclt2026;H:false;;", dot: "var(--warn)", qr: false, cap: "Not a link — an auto-join" }
    ];
    var chips = $("sampleChips");
    SAMPLES.forEach(function (s) {
      var b = document.createElement("button");
      b.className = "chip";
      b.innerHTML = '<span class="cdot" style="background:' + s.dot + '"></span>' + esc(s.label);
      b.addEventListener("click", function () { runAnalysis(s.url, "sample"); });
      chips.appendChild(b);
    });
    var tiles = $("qrTiles");
    SAMPLES.filter(function (s) { return s.qr; }).forEach(function (s) {
      var b = document.createElement("button");
      b.className = "qr-tile";
      b.setAttribute("aria-label", "Analyze sample: " + s.label);
      var imgHtml = '<span style="color:#5b675f; font-size:.85rem;">QR unavailable offline</span>';
      if (typeof qrcode !== "undefined") {
        try {
          var qr = qrcode(0, "M");
          qr.addData(s.url);
          qr.make();
          imgHtml = qr.createSvgTag({ cellSize: 5, margin: 8, scalable: true });
        } catch (e) { imgHtml = '<span style="color:#5b675f; font-size:.85rem;">QR unavailable</span>'; }
      }
      b.innerHTML = '<span class="qr-img">' + imgHtml + '</span><span class="qr-cap"><b>' + esc(s.label) + '</b><span>' + esc(s.cap) + '</span></span>';
      b.addEventListener("click", function () { runAnalysis(s.url, "sample"); });
      tiles.appendChild(b);
    });
