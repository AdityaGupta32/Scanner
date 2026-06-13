import asyncio
from urllib.parse import urlparse, urljoin
from typing import Set, List, Tuple, Dict, Any, Optional
import aiohttp
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

class Spider:
    def __init__(self, start_url: str, max_pages: int = 10, 
                 auth_mode: str = "none", login_url: str = None, 
                 username: str = None, password: str = None):
        self.start_url = start_url
        self.base_url = start_url
        self.auth_mode = auth_mode
        self.login_url = login_url
        self.username = username
        self.password = password
        self.visited_urls: Set[str] = set()
        self.found_links: Set[str] = set()
        self.found_links.add(start_url)
        self.max_pages = max_pages
        self.domain = urlparse(start_url).netloc
        
    def _is_internal(self, url: str) -> bool:
        netloc = urlparse(url).netloc
        # Handle localhost/127.0.0.1 mismatch
        if "localhost" in self.domain and "127.0.0.1" in netloc: return True
        if "127.0.0.1" in self.domain and "localhost" in netloc: return True
        return netloc == self.domain

    async def crawl(self) -> Tuple[List[str], List[Dict]]:
        """
        Main crawl method.
        Returns (crawled_urls, cookies)
        """
        print(f"[*] Starting Crawl on {self.base_url}")
        cookies = []
        
        # Try Dynamic Crawl
        try:
            print("[*] Attempting Dynamic Crawl (Playwright)...")
            
            headless = True
            if self.auth_mode == "interactive":
                headless = False
                print("[!] Launching Browser in INTERACTIVE mode")
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=headless)
                # Create context with custom UA
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scancrypt/2.0 (Dynamic)"
                )
                page = await context.new_page()
                
                # --- Authentication Logic ---
                if self.auth_mode == "interactive":
                     print("[*] Opening Browser for Interactive Login...")
                     target = self.login_url if self.login_url else self.base_url
                     try:
                         await page.goto(target, timeout=60000)
                         
                         # Inject floating "Continue" button with click flag
                         await page.evaluate('''
                             () => {
                                 window.__scancrypt_continue__ = false;
                                 const btn = document.createElement('button');
                                 btn.id = 'scancrypt-continue-btn';
                                 btn.innerHTML = '✓ Click Here to Continue Scan';
                                 btn.style.cssText = `
                                     position: fixed;
                                     bottom: 20px;
                                     right: 20px;
                                     z-index: 999999;
                                     padding: 14px 28px;
                                     background: linear-gradient(135deg, #10b981, #059669);
                                     color: white;
                                     font-size: 15px;
                                     font-weight: 600;
                                     border: none;
                                     border-radius: 14px;
                                     cursor: pointer;
                                     box-shadow: 0 4px 25px rgba(16, 185, 129, 0.5);
                                     font-family: system-ui, -apple-system, sans-serif;
                                     transition: transform 0.2s, box-shadow 0.2s;
                                 `;
                                 btn.onmouseover = () => {
                                     btn.style.transform = 'scale(1.05)';
                                     btn.style.boxShadow = '0 6px 35px rgba(16, 185, 129, 0.7)';
                                 };
                                 btn.onmouseout = () => {
                                     btn.style.transform = 'scale(1)';
                                     btn.style.boxShadow = '0 4px 25px rgba(16, 185, 129, 0.5)';
                                 };
                                 btn.onclick = () => {
                                     window.__scancrypt_continue__ = true;
                                     btn.innerHTML = '⏳ Scanning...';
                                     btn.style.background = '#374151';
                                     btn.style.cursor = 'wait';
                                 };
                                 document.body.appendChild(btn);
                             }
                         ''')
                         
                         print("[*] Login in the browser, then click the green 'Continue' button...")
                         
                         # Wait for user to click button (max 5 minutes)
                         await page.wait_for_function('window.__scancrypt_continue__ === true', timeout=300000)
                         
                         print("[*] Continue button clicked! Resuming scan...")
                     except Exception as e:
                         print(f"[!] Interactive Login Warning: {e}")

                elif self.auth_mode == "auto" and self.login_url and self.username and self.password:
                     print(f"[*] Attempting Auto Login at {self.login_url}")
                     try:
                         await page.goto(self.login_url, timeout=30000)
                         # Heuristic fill
                         await page.fill('input[type="text"], input[type="email"], input[name="user"], input[name="username"]', self.username)
                         await page.fill('input[type="password"]', self.password)
                         await page.press('input[type="password"]', 'Enter')
                         await page.wait_for_timeout(5000)
                         print("[*] Auto Login submitted")
                     except Exception as e:
                         print(f"[!] Auto Login Failed: {e}")
                
                # Capture Cookies after auth
                cookies = await context.cookies()
                print(f"[*] Captured {len(cookies)} cookies")
                
                queue = [self.base_url]
                self.visited_urls.add(self.base_url) # Start with base
                
                while queue and len(self.visited_urls) < self.max_pages:
                    url = queue.pop(0)
                    
                    print(f"[*] Visiting (Dynamic): {url}")
                    try:
                        await page.goto(url, timeout=15000, wait_until="networkidle")
                        
                        # Extract Links from <a> tags
                        links = await page.evaluate("""
                            () => Array.from(document.querySelectorAll('a')).map(a => a.href)
                        """)

                        # Extract Form Action URLs (GET forms become crawlable)
                        form_urls = await page.evaluate("""
                            () => Array.from(document.querySelectorAll('form')).map(f => {
                                const action = f.action || window.location.href;
                                if (f.method && f.method.toLowerCase() === 'post') return null;
                                // Build query string from input defaults
                                const inputs = Array.from(f.querySelectorAll('input[name]'));
                                const params = inputs.map(i => encodeURIComponent(i.name) + '=' + encodeURIComponent(i.value || 'test')).join('&');
                                return params ? action + '?' + params : action;
                            }).filter(Boolean)
                        """)

                        all_urls = links + form_urls
                        for full_url in all_urls:
                            parsed = urlparse(full_url)
                            if not parsed.scheme or not parsed.netloc: continue

                            clean_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                            if parsed.query: clean_url += "?" + parsed.query

                            if self._is_internal(clean_url):
                                 if clean_url not in self.visited_urls and clean_url not in queue:
                                     self.visited_urls.add(clean_url)
                                     queue.append(clean_url)

                    except Exception as e:
                        print(f"[!] Error crawling {url}: {e}")
                
                await browser.close()
                print(f"[*] Dynamic Crawl Success. Found {len(self.visited_urls)} URLs.")
                return list(self.visited_urls), cookies

        except Exception as e:
            print(f"[!] Dynamic Crawl Failed: {e}")
            print("[*] Falling back to Static Crawl (BeautifulSoup)...")
            return await self.crawl_static()

    async def crawl_static(self) -> Tuple[List[str], List[Dict]]:
        """Fallback static crawler using aiohttp + BeautifulSoup"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, timeout=10, ssl=False) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, "html.parser")
                        self.visited_urls.add(self.base_url)

                        # Extract <a href> links
                        for a_tag in soup.find_all("a", href=True):
                            href = a_tag["href"]
                            full_url = urljoin(self.base_url, href)
                            if self._is_internal(full_url):
                                self.visited_urls.add(full_url)

                        # Extract GET <form> action URLs with param placeholders
                        for form in soup.find_all("form"):
                            method = form.get("method", "get").lower()
                            action = form.get("action", "")
                            form_url = urljoin(self.base_url, action) if action else self.base_url

                            if method == "get":
                                # Build query string from input fields
                                params = {}
                                for inp in form.find_all("input", attrs={"name": True}):
                                    itype = inp.get("type", "text").lower()
                                    if itype not in ("submit", "button", "image", "reset"):
                                        params[inp["name"]] = inp.get("value", "test")
                                if params:
                                    from urllib.parse import urlencode
                                    form_url += "?" + urlencode(params)

                            if self._is_internal(form_url):
                                self.visited_urls.add(form_url)

                        print(f"[*] Static Crawl Success. Found {len(self.visited_urls)} URLs.")
                    else:
                        print(f"[!] Static Crawl Failed: HTTP {response.status}")
        except Exception as e:
            import traceback
            print(f"[!] Static Crawl Error: {e}\n{traceback.format_exc()}")

        return list(self.visited_urls), []
