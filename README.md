# luv booth

A realtime online photo booth for two people, no matter the distance. One
person starts a room and shares a short code; the other joins with it. Once
connected, both live webcam feeds appear side by side, and together you can
capture a 4-photo strip with a countdown, filters, and a caption — styled
like a real photo-booth print — and download it as a PNG.

No backend, no database, no accounts. Video is peer-to-peer over WebRTC via
[PeerJS](https://peerjs.com/)'s free public cloud signaling broker.

## Run it locally

This is a single static file — any local web server works:

```bash
python3 -m http.server 8080
# then open http://localhost:8080
```

or

```bash
npx serve .
```

Camera access requires a "secure context": `localhost` is fine for local
testing, but once deployed the site must be served over HTTPS (both
Netlify and GitHub Pages provide this automatically).

## Deploy

**Netlify** (if you have the CLI and an account):

```bash
npm install -g netlify-cli
netlify login
netlify deploy --prod
```

**GitHub Pages**: this repo includes `.github/workflows/deploy-pages.yml`,
which builds and publishes the site automatically on every push. In the
repo's Settings → Pages, make sure the source is set to "GitHub Actions"
(only needed once).

## Testing the two-person connection

You need two separate browser sessions on two different devices (or two
different browsers/profiles on one device, or one regular window + one
incognito window):

1. Open the live URL on device A. Click **start a room** and allow camera
   access. A short code appears near the top of the booth card.
2. Open the live URL on device B. Type that code into **join with a code**
   and allow camera access there too.
3. Both video feeds should appear side by side within a few seconds. If it
   sits on "waiting for them to join…", double-check the code and that both
   devices allowed camera permissions.
4. Click **start strip** — a 3-2-1 countdown runs before each shot. Both
   people appear in every frame.
5. Click **download strip** to save the finished PNG.

Notes:
- Camera permission prompts must be accepted on both devices — if either is
  denied or blocked, that side's status line will say so.
- Some strict corporate/mobile networks block the peer-to-peer connection
  outright (no TURN relay is configured); if the two sides never connect,
  try a different network (e.g. switch off VPN, or use home wifi instead of
  a locked-down office network).
