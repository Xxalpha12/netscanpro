"""
CyberScan Pro - Screenshot Capture Module
Captures screenshots of web targets using requests + PIL.
Works on Render free tier without a headless browser.
Falls back to HTTP response preview if screenshot fails.
"""

import requests
import os
from io import BytesIO
from modules.logger import get_logger

logger = get_logger(__name__)

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "screenshots")

requests.packages.urllib3.disable_warnings()


class ScreenshotCapture:
    """
    Captures website screenshots using screenshotting APIs.
    Uses free tier of screenshot services — no headless browser needed.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    def capture(self, url: str, session_id: str) -> str | None:
        """
        Capture screenshot of URL.
        Returns path to saved image or None if failed.
        """
        # Ensure URL has scheme
        if not url.startswith("http"):
            url = f"http://{url}"

        filename = f"screenshot_{session_id}.png"
        filepath = os.path.join(OUTPUT_DIR, filename)

        # Try method 1: screenshotapi.net (free tier)
        result = self._try_screenshotapi(url, filepath)
        if result:
            return result

        # Try method 2: urlbox.io free tier
        result = self._try_urlbox(url, filepath)
        if result:
            return result

        # Try method 3: Generate HTML preview thumbnail
        result = self._generate_html_preview(url, filepath, session_id)
        if result:
            return result

        logger.warning(f"All screenshot methods failed for {url}")
        return None

    def _try_screenshotapi(self, url: str, filepath: str) -> str | None:
        """Use screenshotapi.net free tier."""
        try:
            api_url = f"https://screenshotapi.net/api/v1/screenshot"
            params = {
                "token": "SCREENSHOTAPI_FREE",
                "url": url,
                "width": 1280,
                "height": 800,
                "output": "image",
                "file_type": "png"
            }
            r = requests.get(api_url, params=params, timeout=self.timeout)
            if r.status_code == 200 and r.headers.get("content-type", "").startswith("image"):
                with open(filepath, "wb") as f:
                    f.write(r.content)
                logger.info(f"Screenshot saved via screenshotapi: {filepath}")
                return filepath
        except Exception as e:
            logger.warning(f"screenshotapi failed: {e}")
        return None

    def _try_urlbox(self, url: str, filepath: str) -> str | None:
        """Use thum.io free screenshot service."""
        try:
            import urllib.parse
            encoded = urllib.parse.quote(url, safe="")
            api_url = f"https://image.thum.io/get/width/1280/crop/800/{encoded}"
            r = requests.get(api_url, timeout=self.timeout, verify=False)
            if r.status_code == 200 and len(r.content) > 5000:
                with open(filepath, "wb") as f:
                    f.write(r.content)
                logger.info(f"Screenshot saved via thum.io: {filepath}")
                return filepath
        except Exception as e:
            logger.warning(f"thum.io failed: {e}")
        return None

    def _generate_html_preview(self, url: str, filepath: str, session_id: str) -> str | None:
        """
        Generate a simple HTML-based preview image showing
        server headers and response info when screenshot APIs fail.
        """
        try:
            from PIL import Image, ImageDraw, ImageFont
            import textwrap

            r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
            server = r.headers.get("Server", "Unknown")
            powered = r.headers.get("X-Powered-By", "")
            status = r.status_code
            title = ""

            # Try extract page title
            if b"<title>" in r.content.lower():
                import re
                match = re.search(rb"<title>(.*?)</title>", r.content, re.IGNORECASE)
                if match:
                    title = match.group(1).decode("utf-8", errors="ignore")[:60]

            # Create preview image
            img = Image.new("RGB", (800, 400), color=(8, 12, 20))
            draw = ImageDraw.Draw(img)

            # Header bar
            draw.rectangle([0, 0, 800, 50], fill=(0, 40, 60))
            draw.rectangle([0, 48, 800, 50], fill=(0, 200, 255))

            # URL bar
            draw.rectangle([10, 10, 790, 38], fill=(10, 20, 35), outline=(0, 200, 255, 100))
            draw.text((20, 16), f"  {url}", fill=(0, 200, 255))

            # Status indicator
            status_color = (0, 200, 100) if status == 200 else (255, 100, 50)
            draw.ellipse([760, 16, 778, 34], fill=status_color)

            # Content area
            y = 70
            info_lines = [
                f"HTTP Status:    {status}",
                f"Server:         {server}",
                f"Powered By:     {powered or 'Not disclosed'}",
                f"Title:          {title or 'No title found'}",
                f"",
                f"Content-Type:   {r.headers.get('Content-Type', 'Unknown')}",
                f"Content-Length: {r.headers.get('Content-Length', 'Unknown')}",
            ]

            for line in info_lines:
                color = (0, 200, 255) if ":" in line else (100, 150, 180)
                draw.text((40, y), line, fill=color)
                y += 28

            # CyberScan Pro watermark
            draw.text((20, 370), "CyberScan Pro — Automated Vulnerability Assessment", fill=(30, 60, 80))

            img.save(filepath, format="PNG")
            logger.info(f"HTML preview generated: {filepath}")
            return filepath

        except Exception as e:
            logger.warning(f"HTML preview generation failed: {e}")
        return None

    @staticmethod
    def get_screenshot_url(session_id: str) -> str:
        """Return the URL path to access a screenshot."""
        return f"/screenshots/{session_id}"
