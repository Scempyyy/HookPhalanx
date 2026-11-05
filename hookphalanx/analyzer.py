"""Core URL sandbox analyzer and phishing heuristic engine."""

import html.parser
import ipaddress
import re
import socket
import ssl
import urllib.parse
import urllib.request
from typing import Dict, List, Any, Optional, Tuple

HIGH_RISK_TLDS = {
    "xyz", "top", "work", "click", "loan", "tk", "ml", "ga", "cf", "gq", 
    "buzz", "fit", "rest", "surf", "casa", "country", "monster", "icu"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "tiny.cc", "goo.gl", "bit.do", "shorte.st"
}

TARGETED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
    "instagram", "chase", "wellsfargo", "bankofamerica", "coinbase", "binance",
    "steam", "spotify", "dropbox", "dhl", "fedex", "usps"
]

PHISHING_KEYWORDS = [
    (r"\b(urgent|immediate|immediately)\b", "Urgency pressure trigger", 10),
    (r"\b(account.*(suspend|terminat|lock|restrict))\b", "Account threat / suspension claim", 25),
    (r"\b(verify.*identity|update.*billing|confirm.*password)\b", "Credential/identity harvesting prompt", 20),
    (r"\b(unauthorized.*(access|activity|charge))\b", "Panic induction (unauthorized activity)", 20),
    (r"\b(within\s+\d+\s+(hours?|minutes?|days?))\b", "Artificial time limit pressure", 15),
    (r"\b(claim.*prize|lottery|winner|inherited)\b", "Advance fee / prize lure", 20),
]

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


class HTMLThreatParser(html.parser.HTMLParser):
    """Parses HTML for suspicious forms, scripts, iframes, and meta redirects."""
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.title = ""
        self.in_title = False
        self.forms: List[Dict[str, Any]] = []
        self.current_form: Optional[Dict[str, Any]] = None
        self.has_password_field = False
        self.has_credit_card_field = False
        self.iframes: List[str] = []
        self.meta_redirect: Optional[str] = None
        self.text_content: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()

        if tag_lower == "title":
            self.in_title = True
        elif tag_lower == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            self.current_form = {"action": action, "method": method, "inputs": []}
        elif tag_lower == "input":
            itype = attr_dict.get("type", "text").lower()
            iname = attr_dict.get("name", "").lower()
            if self.current_form is not None:
                self.current_form["inputs"].append({"type": itype, "name": iname})
            if itype == "password":
                self.has_password_field = True
            if any(k in iname for k in ["card", "cvv", "ccnum", "exp"]):
                self.has_credit_card_field = True
        elif tag_lower == "iframe":
            src = attr_dict.get("src", "")
            if src:
                self.iframes.append(src)
        elif tag_lower == "meta":
            equiv = attr_dict.get("http-equiv", "").lower()
            content = attr_dict.get("content", "")
            if equiv == "refresh" and "url=" in content.lower():
                parts = content.lower().split("url=", 1)
                if len(parts) > 1:
                    self.meta_redirect = parts[1].strip()

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower == "title":
            self.in_title = False
        elif tag_lower == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def handle_data(self, data: str):
        clean = data.strip()
        if self.in_title:
            self.title += data
        if clean:
            self.text_content.append(clean)


def is_private_host(hostname: str) -> bool:
    """Checks if hostname resolves to private/loopback/link-local address."""
    try:
        ip = ipaddress.ip_address(hostname)
        for net in PRIVATE_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            for net in PRIVATE_NETWORKS:
                if ip in net:
                    return True
    except Exception:
        pass
    return False


class PhishingAnalyzer:
    """Multi-stage URL sandbox, redirection analyzer, and phishing heuristic engine."""

    def __init__(self, allow_private: bool = False, timeout: int = 6):
        self.allow_private = allow_private
        self.timeout = timeout

    def analyze(self, raw_url: str, fetch_body: bool = True) -> Dict[str, Any]:
        """Runs full static and dynamic sandbox inspection on target URL."""
        if not raw_url.startswith(("http://", "https://")):
            raw_url = "https://" + raw_url

        parsed = urllib.parse.urlparse(raw_url)
        hostname = (parsed.hostname or "").lower()

        indicators: List[Dict[str, Any]] = []
        score = 0

        # Check SSRF / Private IP protection
        if not self.allow_private and is_private_host(hostname):
            indicators.append({
                "severity": "CRITICAL",
                "points": 90,
                "title": "Private/Local Network Target (SSRF Danger)",
                "detail": f"Host '{hostname}' resolves to a local or internal IP range. Access blocked in sandbox."
            })
            return {
                "url": raw_url,
                "hostname": hostname,
                "score": 90,
                "grade": "MALICIOUS",
                "indicators": indicators,
                "hops": [],
                "page_info": {"title": "Access Blocked", "reachable": False}
            }

        # 1. Hostname heuristics
        # Punycode / IDN
        if hostname.startswith("xn--") or any(ord(c) > 127 for c in hostname):
            score += 35
            indicators.append({
                "severity": "HIGH",
                "points": 35,
                "title": "Punycode / Homograph Domain Detected",
                "detail": f"Domain '{hostname}' uses internationalized characters often abused to visually spoof legitimate domains."
            })

        # Direct IP Address as host
        try:
            ipaddress.ip_address(hostname)
            score += 30
            indicators.append({
                "severity": "HIGH",
                "points": 30,
                "title": "Direct IP Address Host",
                "detail": f"Host is an IP literal ({hostname}) rather than a registered domain name."
            })
        except ValueError:
            pass

        # High-risk TLD
        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in HIGH_RISK_TLDS:
            score += 20
            indicators.append({
                "severity": "MEDIUM",
                "points": 20,
                "title": f"High-Abuse Top-Level Domain (.{tld})",
                "detail": f"TLD '.{tld}' has a statistically elevated frequency of phishing and malicious infrastructure."
            })

        # Known URL Shortener
        if hostname in KNOWN_SHORTENERS:
            score += 15
            indicators.append({
                "severity": "LOW",
                "points": 15,
                "title": "URL Shortener Detected",
                "detail": f"'{hostname}' obfuscates the final destination target."
            })

        # Brand spoofing in subdomains / prefix
        for brand in TARGETED_BRANDS:
            if brand in hostname:
                parts = hostname.split(".")
                # legitimate main domain is e.g. paypal.com
                main_domain = ".".join(parts[-2:]) if len(parts) >= 2 else parts[0]
                if brand not in main_domain:
                    score += 45
                    indicators.append({
                        "severity": "CRITICAL",
                        "points": 45,
                        "title": f"Deceptive Brand Keyword Implantation ({brand})",
                        "detail": f"Brand name '{brand}' appears in subdomain or path while main domain is '{main_domain}'."
                    })
                    break

        # Excessive subdomain depth
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) > 4:
            score += 15
            indicators.append({
                "severity": "MEDIUM",
                "points": 15,
                "title": "Excessive Subdomain Depth",
                "detail": f"Domain contains {len(subdomain_parts)} levels, common in automated subdomain spoofing."
            })

        # Unencrypted HTTP transport
        if parsed.scheme == "http":
            score += 10
            indicators.append({
                "severity": "LOW",
                "points": 10,
                "title": "Unencrypted Plaintext HTTP",
                "detail": "Connection lacks TLS encryption. Any credentials submitted would travel in cleartext."
            })

        # 2. Redirection and Response Dynamic Inspection
        hops = []
        page_info = {
            "title": "",
            "reachable": False,
            "status_code": None,
            "content_type": "",
            "has_forms": False,
            "has_password_field": False,
            "has_credit_card_field": False,
            "meta_redirect": None
        }

        if fetch_body:
            current_target = raw_url
            max_hops = 6
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            for hop_idx in range(max_hops):
                req = urllib.request.Request(
                    current_target,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HookPhalanx/0.1 Sandbox",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                    }
                )

                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None

                opener = urllib.request.build_opener(NoRedirect)
                try:
                    with opener.open(req, timeout=self.timeout) as resp:
                        status = resp.status
                        content_type = resp.headers.get("Content-Type", "")
                        hops.append({"hop": hop_idx + 1, "url": current_target, "status": status})
                        
                        page_info["reachable"] = True
                        page_info["status_code"] = status
                        page_info["content_type"] = content_type

                        if "text/html" in content_type:
                            raw_html = resp.read(256 * 1024).decode("utf-8", errors="replace")
                            parser = HTMLThreatParser(current_target)
                            try:
                                parser.feed(raw_html)
                            except Exception:
                                pass

                            page_info["title"] = parser.title.strip()
                            page_info["has_forms"] = len(parser.forms) > 0
                            page_info["has_password_field"] = parser.has_password_field
                            page_info["has_credit_card_field"] = parser.has_credit_card_field
                            page_info["meta_redirect"] = parser.meta_redirect

                            # Analyze page contents
                            if parser.has_password_field:
                                if parsed.scheme == "http":
                                    score += 35
                                    indicators.append({
                                        "severity": "CRITICAL",
                                        "points": 35,
                                        "title": "Cleartext Password Form",
                                        "detail": "Login password field served over unencrypted HTTP."
                                    })
                                else:
                                    score += 15
                                    indicators.append({
                                        "severity": "MEDIUM",
                                        "points": 15,
                                        "title": "Credential Harvest Field Present",
                                        "detail": "Page contains password input field; user credentials requested."
                                    })

                            if parser.has_credit_card_field:
                                score += 30
                                indicators.append({
                                    "severity": "HIGH",
                                    "points": 30,
                                    "title": "Financial Card Data Request",
                                    "detail": "Form requests credit card numbers or CVV security codes."
                                })

                            # Check text for urgency/phishing triggers
                            combined_text = " ".join(parser.text_content)
                            for pattern, desc, pts in PHISHING_KEYWORDS:
                                if re.search(pattern, combined_text, re.IGNORECASE):
                                    score += pts
                                    indicators.append({
                                        "severity": "MEDIUM" if pts <= 15 else "HIGH",
                                        "points": pts,
                                        "title": f"Social Engineering Cue: {desc}",
                                        "detail": f"Matched pattern '{pattern}' in page content."
                                    })
                        break
                except urllib.error.HTTPError as e:
                    hops.append({"hop": hop_idx + 1, "url": current_target, "status": e.code})
                    if e.code in (301, 302, 303, 307, 308):
                        new_target = e.headers.get("Location")
                        if new_target:
                            current_target = urllib.parse.urljoin(current_target, new_target)
                            continue
                    page_info["status_code"] = e.code
                    break
                except Exception as e:
                    hops.append({"hop": hop_idx + 1, "url": current_target, "error": str(e)})
                    break

        # Calculate final risk score and grade
        final_score = min(100, max(0, score))
        if final_score >= 70:
            grade = "MALICIOUS"
        elif final_score >= 45:
            grade = "DANGEROUS"
        elif final_score >= 20:
            grade = "SUSPICIOUS"
        else:
            grade = "SAFE"

        return {
            "url": raw_url,
            "hostname": hostname,
            "score": final_score,
            "grade": grade,
            "indicators": indicators,
            "hops": hops,
            "page_info": page_info
        }
