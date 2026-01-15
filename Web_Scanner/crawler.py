# crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style

def crawl_with_params(url, max_depth=2, timeout=5):
    """
    Crawl site starting at url up to max_depth.
    Returns: (found_links_set, params_map)
     - found_links_set: set of discovered URLs within domain
     - params_map: dict { page_url: {"query_params": set(...), "form_inputs": set(...)} }
    """
    visited = set()
    found = set()
    params_map = {}

    base_netloc = urlparse(url).netloc

    def _crawl(u, depth):
        if depth > max_depth or u in visited:
            return
        visited.add(u)
        try:
            r = requests.get(u, timeout=timeout)
            text = r.text or ""
            soup = BeautifulSoup(text, "html.parser")
        except Exception:
            return

        # query params from url
        try:
            qps = set(parse_qs(urlparse(u).query).keys())
        except Exception:
            qps = set()

        # form inputs
        form_inputs = set()
        try:
            for form in soup.find_all("form"):
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        form_inputs.add(name)
        except Exception:
            pass

        params_map[u] = {"query_params": qps, "form_inputs": form_inputs}

        # find links
        try:
            for a in soup.find_all("a", href=True):
                href = a["href"]
                full = urljoin(u, href)
                parsed = urlparse(full)
                # only keep same domain
                if parsed.netloc == base_netloc:
                    if full not in visited:
                        found.add(full)
                        _crawl(full, depth + 1)
        except Exception:
            pass

    _crawl(url, 0)
    return found, params_map


def crawl(url, max_depth=2, timeout=5):
    """Simple URL discovery (no params) kept for compatibility."""
    links, _ = crawl_with_params(url, max_depth=max_depth, timeout=timeout)
    return links
