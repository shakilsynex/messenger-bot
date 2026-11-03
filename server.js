const express = require("express");
const crypto = require("crypto");

const app = express();

// Keep raw body so we can verify Meta's signature
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));

const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const PAGE_ACCESS_TOKEN = process.env.PAGE_ACCESS_TOKEN;
const APP_SECRET = process.env.APP_SECRET; // optional but recommended

// ---------- Replies (edit here) ----------
const EGG_REPLY = `🦆 অরিজিনাল দেশি পাতিহাঁসের বীজ ডিম 🥚❤️

💰 মূল্য: ৫০ টাকা প্রতি পিস।

📦 অর্ডার পদ্ধতি:
অর্ডার কনফার্ম করতে ২০০ টাকা অগ্রিম দিতে হবে। বাকি টাকা পণ্য হাতে পেয়ে ক্যাশ অন ডেলিভারিতে পরিশোধ করতে পারবেন।

💳 পেমেন্ট মাধ্যম: বিকাশ ও নগদ (পার্সোনাল)
📱 পেমেন্ট নম্বর: 01627994154

🚚 ডেলিভারি: সারা বাংলাদেশে কুরিয়ারের মাধ্যমে ডেলিভারি দেওয়া হয়।

📩 অর্ডার করতে আপনার নাম, সম্পূর্ণ ঠিকানা ও মোবাইল নম্বর পাঠিয়ে দিন।

❤️ পাহাড়ের চাষী — পাহাড় থেকে আপনাদের আস্থায়।`;

const LOCATION_REPLY = "আপনার লোকেশন কোথায় ভাই?";

const PRICE_GENERIC_REPLY =
  "কোন পণ্যের দাম জানতে চান ভাই? বীজ ডিম, মুরগি, হাঁস নাকি মসলা?";

// ---------- Rules ----------
// Order matters: the first matching rule wins.
// Keywords are written in normal spelling; spelling variants
// (ী/ি, ূ/ু, ঁ) are handled automatically by normalize().
const RULES = [
  {
    name: "egg",
    keywords: ["ডিম", "বীজ", "বিজ", "dim", "egg", "biz"],
    reply: EGG_REPLY,
  },
  {
    name: "bird",
    keywords: ["মুরগি", "মুরগী", "হাঁস", "হাস", "murgi", "hash", "duck", "chicken"],
    reply: LOCATION_REPLY,
  },
  {
    name: "price",
    keywords: ["দাম", "price", "কত", "rate", "dam"],
    reply: PRICE_GENERIC_REPLY,
  },
];

// ---------- Helpers ----------
function normalize(text) {
  return String(text)
    .toLowerCase()
    .replace(/ঁ/g, "")
    .replace(/ী/g, "ি")
    .replace(/ূ/g, "ু")
    .replace(/\s+/g, " ")
    .trim();
}

const NORMALIZED_RULES = RULES.map((r) => ({
  ...r,
  keywords: r.keywords.map(normalize),
}));

function findReply(text) {
  const t = normalize(text);
  for (const rule of NORMALIZED_RULES) {
    if (rule.keywords.some((k) => t.includes(k))) return rule.reply;
  }
  return null; // no match: stay silent so you can reply manually
}

async function sendText(psid, text) {
  const res = await fetch(
    `https://graph.facebook.com/v21.0/me/messages?access_token=${PAGE_ACCESS_TOKEN}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient: { id: psid },
        messaging_type: "RESPONSE",
        message: { text },
      }),
    }
  );
  if (!res.ok) console.error("Send API error:", res.status, await res.text());
}

function validSignature(req) {
  if (!APP_SECRET) return true; // skip if not configured
  const sig = req.get("x-hub-signature-256");
  if (!sig || !req.rawBody) return false;
  const expected =
    "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

// ---------- Routes ----------
app.get("/", (_req, res) => res.send("Bot is running ✅"));

// Meta calls this once to verify your webhook
app.get("/webhook", (req, res) => {
  if (
    req.query["hub.mode"] === "subscribe" &&
    req.query["hub.verify_token"] === VERIFY_TOKEN
  ) {
    return res.status(200).send(req.query["hub.challenge"]);
  }
  res.sendStatus(403);
});

// Meta sends customer messages here
app.post("/webhook", (req, res) => {
  if (!validSignature(req)) return res.sendStatus(403);
  res.sendStatus(200); // reply to Meta immediately

  const body = req.body;
  if (body.object !== "page") return;

  for (const entry of body.entry || []) {
    for (const event of entry.messaging || []) {
      const msg = event.message;
      if (!msg || msg.is_echo || !msg.text) continue; // ignore echoes, images, voice
      const reply = findReply(msg.text);
      if (reply) sendText(event.sender.id, reply).catch(console.error);
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Listening on", PORT));
