# SafeBrowse – Real-Time Phishing Detection

A full-stack phishing detection system consisting of:
- **Chrome Extension (MV3)** – Real-time URL scanning via AI
- **Admin Portal** – React dashboard with threat intelligence, ML model monitoring, and endpoint management  
- **AI Backend** – ModernBERT model hosted on Hugging Face Spaces

---

## 🚀 Quick Start

```bash
npm install
npm run dev         # Development server on http://localhost:3000
npm run build       # Build web portal for Vercel
npm run build:extension  # Build Chrome extension → extension/dist/
```

---

## 🌐 Deployment

### 1. Web Portal → Vercel

```bash
# Push to GitHub, then connect repo to Vercel
# Vercel auto-detects vite.config.ts and deploys

# OR deploy via CLI:
npx vercel
```

**Environment Variables** (set in Vercel dashboard):
- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`
- `SUPABASE_URL` (optional fallback to `VITE_SUPABASE_URL`)
- `SUPABASE_ANON_KEY` (optional fallback to `VITE_SUPABASE_ANON_KEY`)
- `SUPABASE_SERVICE_ROLE_KEY` (recommended for server-side logging and endpoint linking)
- `GOOGLE_SAFE_BROWSING_API_KEY` (optional, enables Google Safe Browsing checks)
- `VIRUSTOTAL_API_KEY` (optional, enables VirusTotal checks)

Use `.env.example` as the template for local + Vercel setup.

> [!IMPORTANT]
> After deploying, update these files with your Vercel URL:
> - `extension/src/background.ts` → `VERCEL_API_URL`
> - `src/components/AdminDashboard.tsx` → SettingsView default URL

---

### 2. Chrome Extension → Sideload (Testing)

```bash
npm run build:extension
```

Then in Chrome:
1. Go to `chrome://extensions`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked** → select the `extension/dist/` folder
4. The SafeBrowse icon appears in your toolbar ✅

### 3. Chrome Extension → Chrome Web Store (Production)

1. Zip the `extension/dist/` folder
2. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
3. Pay the one-time $5 developer fee
4. Upload the zip, fill in store listing, submit for review (~3-7 days)

> [!NOTE]
> For your university FYP demo, sideloading is perfectly sufficient. Chrome Web Store is only needed for public distribution.

---

## 🤖 AI Models

| Model | Host | API |
|-------|------|-----|
| ModernBERT (Transformer) | Hugging Face Spaces | `POST https://-phishing.hf.space/predict` |

**HF API Request:**
```json
POST /predict
{ "url": "https://example.com" }
```

**HF API Response:**
```json
{
  "label": "phishing",
  "confidence": 0.998,
  "phishing_probability": 0.998,
  "legitimate_probability": 0.002,
  "inference_time_ms": 142.5,
  "model_used": "ModernBERT"
}
```

---

## 📁 Project Structure

```
Working/
├── extension/              # Chrome MV3 Extension
│   ├── manifest.json       # Extension config & permissions
│   ├── src/
│   │   ├── background.ts   # Service worker: URL scanning, badge
│   │   ├── content.ts      # Form detection, phishing overlays
│   │   └── popup/
│   │       ├── popup.html  # Popup shell
│   │       └── popup.tsx   # React popup UI (real scan data)
│   └── dist/               # Built extension (load this in Chrome)
│
├── api/                    # Vercel Serverless Functions
│   ├── check-url.ts        # POST /api/check-url → HF proxy
│   ├── health.ts           # GET /api/health → model status
│   └── lib/
│       └── url-features.ts # URL feature extraction (30 features)
│
├── src/
│   ├── components/
│   │   ├── AdminDashboard.tsx  # Full admin portal
│   │   └── ExtensionPopup.tsx  # Demo popup preview
│   └── App.tsx
│
├── vercel.json             # Vercel deployment config
└── README.md
```

---

## 🔒 How It Works

1. User navigates to a URL in Chrome
2. **Background service worker** intercepts via `webNavigation.onCompleted`
3. Sends URL to `POST https://-phishing.hf.space/predict`
4. ModernBERT returns `{label, confidence, phishing_probability}`
5. Badge turns **green** (safe) / **amber** (warning) / **red** (phishing)
6. User clicks extension icon → sees detailed scan results
7. **Content script** separately detects HTTP password forms and shows warnings
