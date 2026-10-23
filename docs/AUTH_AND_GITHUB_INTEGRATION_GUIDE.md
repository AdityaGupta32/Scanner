# VerseScan — Authentication & Direct GitHub Integration Guide
**Version:** 2.0  
**Target Architecture:** Next.js Dashboard + FastAPI Scanner Engine + Supabase / PostgreSQL  

---

## Executive Architecture Overview

```
                      ┌────────────────────────────────────────────────────────┐
                      │                 Client (Next.js Dashboard)              │
                      └──────────────┬──────────────────────────┬──────────────┘
                                     │                          │
                 1. User Auth & OAuth│                          │2. Scan API + JWT
                                     ▼                          ▼
                      ┌──────────────────────┐   Bearer Token   ┌──────────────────────┐
                      │    Supabase Auth     │─────────────────▶│   FastAPI Backend    │
                      │  (Google / GitHub /  │                  │  (JWT Verification & │
                      │   Email + Password)  │                  │   Scanner Engine)    │
                      └──────────────────────┘                  └──────────┬───────────┘
                                                                           │
                                                                           │3. GitHub API
                                                                           ▼
                                                                ┌──────────────────────┐
                                                                │      GitHub API      │
                                                                │  (Cloning, Tarballs, │
                                                                │   Webhooks, Checks)  │
                                                                └──────────────────────┘
```

---

## Part 1: Direct GitHub Integration

### Goal
Allow users to:
1. Paste any GitHub URL (or select from their repositories via OAuth).
2. Directly scan repository source code, workflows, and dependencies without manually hosting it.
3. Automatically trigger security scans on `git push` via GitHub Webhooks.

---

### Step 1.1: GitHub Repository Ingestion Pipeline

Currently, VerseScan crawls live HTTP web endpoints. To scan a GitHub repository directly:

#### Method A: Direct Clone / Tarball Stream (Recommended)
Instead of crawling public HTML pages on `github.com` (which triggers GitHub anti-bot rate limits), download the repository archive directly via GitHub API:

```python
# scanner-engine/github_service.py
import os
import aiohttp
import tempfile
import zipfile
import io

async def download_github_repo(owner: str, repo: str, branch: str = "main", token: str = None) -> str:
    """
    Downloads repository archive directly into a secure sandbox directory.
    Supports both public and private repositories using a GitHub token.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "VerseScan-Engine"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    temp_dir = tempfile.mkdtemp(prefix=f"vs_{owner}_{repo}_")

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                data = await resp.read()
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    z.extractall(temp_dir)
                return temp_dir
            else:
                raise Exception(f"Failed to fetch repo: HTTP {resp.status}")
```

---

### Step 1.2: GitHub Webhook on Push (Continuous Security Audit)

To automatically audit code every time a developer runs `git push`:

1. **In GitHub Repo Settings**:
   - Go to **Settings > Webhooks > Add Webhook**.
   - **Payload URL**: `https://your-api.com/webhooks/github`
   - **Content type**: `application/json`
   - **Secret**: Set a shared HMAC secret key (e.g. `VS_WEBHOOK_SECRET`).
   - **Events**: Select **Just the push event**.

2. **In FastAPI (`main.py`)**:
```python
import hmac
import hashlib
from fastapi import Header, Request

@app.post("/webhooks/github")
async def github_webhook(request: Request, x_hub_signature_256: str = Header(None)):
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "").encode()
    body = await request.body()

    # Validate HMAC signature from GitHub
    signature = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, x_hub_signature_256 or ""):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()
    repo_url = payload.get("repository", {}).get("html_url")
    commit_sha = payload.get("after")

    # Launch automated scan
    scan_id = str(uuid.uuid4())
    asyncio.create_task(run_scan(scan_id=scan_id, target_url=repo_url, max_pages=15))
    return {"status": "scan_dispatched", "scan_id": scan_id}
```

---

## Part 2: User Registration & JWT Authentication

### Why Supabase Auth + JWT?
Your project already has Supabase configured (`dashboard/lib/supabase`). Supabase Auth provides:
- **Instant Email/Password Registration** with verification.
- **Google & GitHub OAuth** out of the box with zero boilerplate.
- **Standards-Compliant JWTs** (`RS256` or `HS256`) that can be validated directly by both the Next.js frontend and the FastAPI backend.

---

### Step 2.1: User Registration in Next.js Dashboard

Create a dedicated registration component/page (`dashboard/app/register/page.tsx`):

```tsx
"use client";
import { useState } from "react";
import { createClient } from "@/lib/supabase/client";
import { useRouter } from "next/navigation";

export default function RegisterPage() {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [fullName, setFullName] = useState("");
    const [error, setError] = useState<string | null>(null);
    const router = useRouter();
    const supabase = createClient();

    const handleRegister = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: {
                    full_name: fullName,
                },
                emailRedirectTo: `${location.origin}/auth/callback`,
            },
        });

        if (error) {
            setError(error.message);
        } else {
            router.push("/dashboard");
        }
    };

    return (
        <form onSubmit={handleRegister} className="space-y-4 max-w-sm mx-auto">
            <input
                type="text"
                placeholder="Full Name"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="w-full p-3 rounded-lg bg-neutral-900 border border-neutral-800 text-white"
                required
            />
            <input
                type="email"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full p-3 rounded-lg bg-neutral-900 border border-neutral-800 text-white"
                required
            />
            <input
                type="password"
                placeholder="Secure Password (min 8 chars)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full p-3 rounded-lg bg-neutral-900 border border-neutral-800 text-white"
                required
            />
            {error && <p className="text-red-400 text-xs">{error}</p>}
            <button type="submit" className="w-full py-3 bg-cyan-500 text-black font-bold rounded-lg hover:bg-cyan-400">
                Create Account
            </button>
        </form>
    );
}
```

---

### Step 2.2: FastAPI JWT Token Verification

In your FastAPI backend (`scanner-engine/main.py`), protect endpoints so only authenticated users can launch scans:

```python
import jwt
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

# Supabase JWT Secret is found in: Supabase Dashboard > Project Settings > API > JWT Settings
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET")

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated"
        )
        user_id = payload.get("sub")
        email = payload.get("email")
        return {"user_id": user_id, "email": email}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

# Usage on Protected Routes:
@app.post("/scan")
async def start_scan(request: ScanRequest, user: dict = Depends(get_current_user)):
    print(f"Scan launched by verified user: {user['email']} ({user['user_id']})")
    request.user_id = user["user_id"]
    ...
```

---

## Part 3: Google & GitHub OAuth Integration

### Step 3.1: Configure Google OAuth

1. **Google Cloud Console**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/).
   - Navigate to **APIs & Services > Credentials > Create Credentials > OAuth client ID**.
   - **Application type**: Web application.
   - **Authorized redirect URIs**:
     ```
     https://<YOUR_SUPABASE_PROJECT_ID>.supabase.co/auth/v1/callback
     ```
   - Copy the generated **Client ID** and **Client Secret**.

2. **In Supabase Dashboard**:
   - Go to **Authentication > Providers > Google**.
   - Toggle **Enable Google provider** to ON.
   - Paste **Client ID** and **Client Secret**.
   - Click **Save**.

---

### Step 3.2: Configure GitHub OAuth

1. **In GitHub**:
   - Go to **GitHub > Settings > Developer Settings > OAuth Apps > New OAuth App**.
   - **Application name**: `VerseScan`
   - **Homepage URL**: `http://localhost:3000` (or production URL)
   - **Authorization callback URL**:
     ```
     https://<YOUR_SUPABASE_PROJECT_ID>.supabase.co/auth/v1/callback
     ```
   - Generate **Client Secret** and copy both ID and Secret.

2. **In Supabase Dashboard**:
   - Go to **Authentication > Providers > GitHub**.
   - Toggle **Enable GitHub provider** to ON.
   - Paste Client ID & Client Secret.
   - Set Scope to: `read:user, repo` (allows scanning private user repositories).

---

### Step 3.3: Login Page Implementation (Google + GitHub + Email)

Update `dashboard/app/login/page.tsx` with one-click OAuth buttons:

```tsx
const handleOAuthLogin = async (provider: "google" | "github") => {
    try {
        setIsLoading(true);
        const { error } = await supabase.auth.signInWithOAuth({
            provider,
            options: {
                redirectTo: `${location.origin}/auth/callback`,
                scopes: provider === "github" ? "read:user repo" : undefined,
            },
        });
        if (error) throw error;
    } catch (err) {
        console.error(`${provider} Login Error:`, err);
        setIsLoading(false);
    }
};
```

**UI Buttons**:
```tsx
<div className="grid grid-cols-2 gap-3 mt-4">
    <button
        onClick={() => handleOAuthLogin("google")}
        className="flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-xs font-semibold text-white transition-all"
    >
        <svg className="w-4 h-4" viewBox="0 0 24 24">...</svg>
        Google
    </button>
    <button
        onClick={() => handleOAuthLogin("github")}
        className="flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-xs font-semibold text-white transition-all"
    >
        <svg className="w-4 h-4" viewBox="0 0 24 24">...</svg>
        GitHub
    </button>
</div>
```

---

## Summary Checklist for Deployment

| Task | Component | Key Configuration |
| :--- | :--- | :--- |
| **Direct GitHub Download** | `scanner-engine/github_service.py` | GitHub Tarball API `/repos/{owner}/{repo}/zipball` |
| **Continuous CI/CD Webhook** | `scanner-engine/main.py` | `POST /webhooks/github` with HMAC SHA256 validation |
| **Email/Password Signup** | `dashboard/app/register/page.tsx` | `supabase.auth.signUp()` |
| **JWT Verification** | `scanner-engine/main.py` | `jwt.decode(token, SUPABASE_JWT_SECRET)` dependency |
| **Google Sign-In** | Google Console + Supabase | OAuth Web Client with Supabase callback URL |
| **GitHub Sign-In** | GitHub Developer + Supabase | OAuth App with `read:user repo` scope |
