"""
CyberScan Pro - Complete Report Generator
Generates both HTML and PDF reports with plain English explanations.
"""

import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from modules.logger import get_logger

logger = get_logger(__name__)

OUTPUT_DIR   = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}

METHODOLOGY = [
    ("1. Subdomain Discovery",  "Queried public APIs and performed DNS bruteforce",           "Hidden attack surfaces and exposed subdomains"),
    ("2. Network Scanning",     "TCP port scan using Nmap/socket scanner",                    "Open ports, running services, software versions"),
    ("3. Service Detection",    "Banner grabbing and version fingerprinting on all open ports","Outdated software, vulnerable service versions"),
    ("4. Web Assessment",       "HTTP security header analysis and vulnerability payload testing","XSS, SQLi, CSRF, directory traversal, open redirects"),
    ("5. CVE Mapping",          "Queried the NVD (National Vulnerability Database) API",      "Known CVEs matching detected service versions with CVSS scores"),
    ("6. Risk Scoring",         "Calculated per-host risk scores based on finding severity",  "Overall security posture and prioritised remediation list"),
]

VULN_EXPLANATIONS = {
    "Missing Security Header: X-Frame-Options": {
        "what": "This website is missing a security instruction that prevents it from being secretly embedded inside another webpage.",
        "means": "An attacker can create a fake webpage that silently loads your site inside it. When a visitor clicks something on the fake page, they are unknowingly clicking on your site — this is called Clickjacking.",
        "impact": "Attackers can trick users into clicking Delete Account, Send Money, or Grant Access buttons on your site without them realizing it.",
        "fix": "Add this line to your web server configuration:\n  X-Frame-Options: SAMEORIGIN\nThis tells browsers to never allow your site to be loaded inside another site's frame.",
        "difficulty": "Easy — 5 minute fix"
    },
    "Missing Security Header: Content-Security-Policy": {
        "what": "The website has no Content Security Policy — a set of rules telling the browser what content is allowed to load.",
        "means": "Without this policy, an attacker who finds any vulnerability can inject and run malicious scripts that steal user data or redirect visitors.",
        "impact": "If an attacker injects JavaScript into your page, it runs completely unchecked — potentially stealing login cookies, credit card numbers, or personal data from every visitor.",
        "fix": "Add this header to your server:\n  Content-Security-Policy: default-src 'self'\nThis only allows content from your own domain.",
        "difficulty": "Medium — requires testing"
    },
    "Missing Security Header: Strict-Transport-Security": {
        "what": "The website is not enforcing HTTPS connections, which means the first visit from a user can be intercepted.",
        "means": "Even if your site supports HTTPS, attackers on the same network can intercept the first request and downgrade it to unencrypted HTTP.",
        "impact": "On public Wi-Fi, attackers can steal passwords and session cookies from your users before they even connect securely.",
        "fix": "Add this header:\n  Strict-Transport-Security: max-age=31536000; includeSubDomains\nThis tells browsers to always use HTTPS for your site.",
        "difficulty": "Easy — 5 minute fix"
    },
    "Missing Security Header: X-Content-Type-Options": {
        "what": "The website is missing a header that prevents browsers from guessing the type of files being served.",
        "means": "Browsers sometimes try to guess file types. If an attacker uploads a file disguised as an image but containing malicious code, the browser might execute it.",
        "impact": "Attackers can upload malicious files that get executed as scripts when viewed by other users.",
        "fix": "Add this header:\n  X-Content-Type-Options: nosniff",
        "difficulty": "Easy — 2 minute fix"
    },
    "Missing Security Header: X-XSS-Protection": {
        "what": "The website is missing a legacy browser-level protection against Cross-Site Scripting attacks.",
        "means": "Older browsers have a built-in XSS filter that needs this header to activate. Without it, some browsers will not attempt to block script injection attacks.",
        "impact": "Users on older browsers are more vulnerable to script injection attacks that can steal their session and personal data.",
        "fix": "Add this header:\n  X-XSS-Protection: 1; mode=block",
        "difficulty": "Easy — 2 minute fix"
    },
    "Missing Security Header: Referrer-Policy": {
        "what": "The website does not control what information is shared when users click links to other websites.",
        "means": "When a user clicks a link leaving your site, their browser automatically tells the next site the full URL they came from — including any sensitive data in the URL.",
        "impact": "Private tokens, user IDs, or session data in URLs can be leaked to third-party websites without the user's knowledge.",
        "fix": "Add this header:\n  Referrer-Policy: strict-origin-when-cross-origin",
        "difficulty": "Easy — 2 minute fix"
    },
    "SQL Injection": {
        "what": "The website passes user input directly into database queries without checking or sanitizing it first.",
        "means": "An attacker can type specially crafted text into a form or URL that manipulates your database — instead of searching for a username, they can extract all usernames and passwords.",
        "impact": "Attackers can steal your entire database, delete all records, bypass login, or take complete control of the database server.",
        "fix": "Never build database queries by combining strings with user input. Use parameterized queries:\n  WRONG:  'SELECT * FROM users WHERE name = ' + userInput\n  RIGHT:  'SELECT * FROM users WHERE name = ?', [userInput]",
        "difficulty": "Medium — requires code changes"
    },
    "Cross-Site Scripting (XSS)": {
        "what": "The website displays user-submitted content without checking it for malicious code first.",
        "means": "An attacker can submit JavaScript code through a form or URL. When other users view that page, the malicious script runs in their browser as if it came from your website.",
        "impact": "Attackers can steal session cookies, redirect users to fake login pages, make the browser perform actions on behalf of the user, or install malware.",
        "fix": "Always encode user input before displaying it on a page. Use HTML escaping on all user-submitted data and implement a Content-Security-Policy header.",
        "difficulty": "Medium — requires code review"
    },
    "Missing CSRF Protection": {
        "what": "Forms on this website do not include a secret token to verify that submissions come from legitimate users.",
        "means": "An attacker can create a hidden form on their site that submits to your website. When a logged-in user visits the attacker's page, their browser silently submits the form.",
        "impact": "Attackers can make users unknowingly transfer money, change passwords, delete accounts, or perform any action the user is authorized to do.",
        "fix": "Add a unique CSRF token to every form and verify it on the server before processing any submission.",
        "difficulty": "Medium — requires code changes"
    },
    "Directory Traversal": {
        "what": "The website allows file paths in URLs that can be manipulated to access files outside the intended folder.",
        "means": "By typing ../ in a URL, an attacker can trick the server into reading files it should never expose — like configuration files containing passwords.",
        "impact": "Attackers can read database credentials, API keys, private keys, and system configuration files from the server.",
        "fix": "Never use user-supplied input directly in file system paths. Always validate that the resolved path starts with your intended base directory.",
        "difficulty": "Medium — requires code changes"
    },
    "Open Redirect": {
        "what": "The website redirects users to URLs specified in request parameters without validating them.",
        "means": "Attackers can send users a link to your trusted website that secretly redirects them to a malicious site. Because the link starts with your domain, users trust it.",
        "impact": "Highly effective phishing attacks — users trust your domain name but end up on a fake login page controlled by the attacker.",
        "fix": "Never redirect to user-supplied URLs. Use a whitelist of allowed redirect destinations or only allow relative paths within your own domain.",
        "difficulty": "Easy — requires code change"
    },
}

def get_explanation(vuln_type):
    if vuln_type in VULN_EXPLANATIONS:
        return VULN_EXPLANATIONS[vuln_type]
    for key, val in VULN_EXPLANATIONS.items():
        if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
            return val
    return {
        "what":   f"A security vulnerability of type '{vuln_type}' was detected on the target.",
        "means":  "This vulnerability could be exploited by an attacker to compromise the security of the target system or its users.",
        "impact": "The specific impact depends on the nature of the vulnerability and the attacker's objectives.",
        "fix":    "Review the technical evidence provided and consult security documentation for this vulnerability type. Consider engaging a qualified security professional for remediation.",
        "difficulty": "Review required"
    }


class ReportGenerator:

    def __init__(self, session_id, target, hosts, web_findings,
                 cve_findings, output_format="both"):
        self.session_id    = session_id
        self.target        = target
        self.hosts         = hosts
        self.web_findings  = self._enrich(web_findings)
        self.cve_findings  = cve_findings
        self.output_format = output_format
        self.generated_at  = datetime.now()
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    def _enrich(self, findings):
        enriched = []
        for f in findings:
            exp = get_explanation(f.get("vuln_type", ""))
            f = dict(f)
            f["plain_what"]       = exp["what"]
            f["plain_means"]      = exp["means"]
            f["plain_impact"]     = exp["impact"]
            f["plain_fix"]        = exp["fix"]
            f["plain_difficulty"] = exp["difficulty"]
            enriched.append(f)
        return enriched

    def _severity_counts(self):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.web_findings + self.cve_findings:
            sev = f.get("severity", "Low")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _risk_rating(self, counts):
        if counts["Critical"] > 0: return "CRITICAL"
        if counts["High"] > 0:     return "HIGH"
        if counts["Medium"] > 0:   return "MEDIUM"
        if counts["Low"] > 0:      return "LOW"
        return "INFORMATIONAL"

    def _all_findings(self):
        merged = []
        for f in self.web_findings:
            merged.append({
                "severity":       f.get("severity"),
                "vuln_type":      f.get("vuln_type"),
                "host_ip":        f.get("host_ip"),
                "recommendation": f.get("recommendation", f.get("plain_fix","")),
            })
        for f in self.cve_findings:
            merged.append({
                "severity":       f.get("severity"),
                "vuln_type":      f.get("cve_id"),
                "host_ip":        f.get("host_ip"),
                "recommendation": f"Update {f.get('service','')} to the latest patched version. Search {f.get('cve_id','')} at nvd.nist.gov.",
            })
        return sorted(merged, key=lambda x: SEVERITY_ORDER.get(x.get("severity","Low"), 4))

    def _context(self):
        counts = self._severity_counts()
        return {
            "report_title":    "Vulnerability Assessment Report",
            "target":          self.target,
            "session_id":      self.session_id,
            "generated_at":    self.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_hosts":     len(self.hosts),
            "total_findings":  len(self.web_findings) + len(self.cve_findings),
            "risk_rating":     self._risk_rating(counts),
            "severity_counts": counts,
            "hosts":           self.hosts,
            "web_findings":    sorted(self.web_findings,  key=lambda x: SEVERITY_ORDER.get(x.get("severity","Low"), 4)),
            "cve_findings":    sorted(self.cve_findings,  key=lambda x: SEVERITY_ORDER.get(x.get("severity","Low"), 4)),
            "all_findings":    self._all_findings(),
            "methodology":     METHODOLOGY,
        }

    def generate(self):
        paths = []
        ts   = self.generated_at.strftime("%Y%m%d_%H%M%S")
        base = f"cyberscanpro_report_{self.session_id}_{ts}"

        if self.output_format in ("html", "both"):
            p = os.path.join(OUTPUT_DIR, f"{base}.html")
            self._html(p)
            paths.append(p)

        if self.output_format in ("pdf", "both"):
            p = os.path.join(OUTPUT_DIR, f"{base}.pdf")
            self._pdf(p)
            paths.append(p)

        return paths

    def _html(self, path):
        env  = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html"])
        )
        tmpl = env.get_template("report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(tmpl.render(**self._context()))
        logger.info(f"HTML report: {path}")

    def _pdf(self, path):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                            Table, TableStyle, HRFlowable,
                                            PageBreak, KeepTogether)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFIED
        except ImportError:
            logger.error("reportlab not installed — PDF skipped")
            return

        ctx = self._context()

        NAVY    = colors.HexColor("#1F3864")
        BLUE    = colors.HexColor("#2E75B6")
        LBLUE   = colors.HexColor("#EBF3FB")
        CRIT    = colors.HexColor("#C00000")
        HIGH    = colors.HexColor("#E74C3C")
        MED     = colors.HexColor("#E67E22")
        LOW_C   = colors.HexColor("#2980B9")
        GREEN   = colors.HexColor("#27AE60")
        NONE_C  = colors.HexColor("#95A5A6")

        SEV_C = {"Critical": CRIT, "High": HIGH, "Medium": MED, "Low": LOW_C, "None": NONE_C}
        RISK_C = {"CRITICAL": CRIT, "HIGH": HIGH, "MEDIUM": MED, "LOW": LOW_C, "INFORMATIONAL": GREEN}

        doc = SimpleDocTemplate(path, pagesize=A4,
            topMargin=2*cm, bottomMargin=2.5*cm,
            leftMargin=2*cm, rightMargin=2*cm,
            title="CyberScan Pro Report", author="Obeh Emmanuel Onoriode")

        FONT = "Helvetica"
        def S(name, **kw):
            from reportlab.lib.styles import ParagraphStyle
            return ParagraphStyle(name, fontName=FONT, **kw)

        TITLE = S("T",  fontSize=20, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER)
        SUB   = S("SB", fontSize=10, textColor=colors.HexColor("#A8C4D8"), alignment=TA_CENTER)
        H1    = S("H1", fontSize=14, textColor=NAVY, fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=6)
        H2    = S("H2", fontSize=11, textColor=BLUE, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
        BD    = S("BD", fontSize=9,  leading=14, spaceAfter=6, alignment=TA_JUSTIFIED)
        SM    = S("SM", fontSize=7.5, textColor=colors.grey, leading=11)
        LB    = S("LB", fontSize=8,  textColor=colors.grey, fontName="Helvetica-Bold")
        PE    = S("PE", fontSize=8.5, leading=13, spaceAfter=3)

        def sp(h=0.3): return Spacer(1, h*cm)
        def hr(): return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC"))

        story = []

        # ── COVER ──────────────────────────────────────────────────────────
        risk     = ctx["risk_rating"]
        risk_col = RISK_C.get(risk, NONE_C)

        cover = Table([[
            Paragraph("🛡️  CyberScan Pro", TITLE),
        ]], colWidths=[17*cm])
        cover.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), NAVY),
            ("TOPPADDING",    (0,0),(-1,-1), 20),
            ("BOTTOMPADDING", (0,0),(-1,-1), 20),
        ]))
        story += [sp(1.5), cover, sp(0.4)]

        sub_tbl = Table([[
            Paragraph("Vulnerability Assessment Report", SUB),
            Paragraph(f"Target: {ctx['target']}", SUB),
            Paragraph(f"Generated: {ctx['generated_at']}", SUB),
        ]], colWidths=[17*cm])
        sub_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#0a1220")),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
        ]))
        story += [sub_tbl, sp(0.6)]

        risk_tbl = Table([[
            Paragraph(f"OVERALL RISK RATING: {risk}",
                      S("R", fontSize=14, textColor=colors.white,
                        fontName="Helvetica-Bold", alignment=TA_CENTER))
        ]], colWidths=[17*cm])
        risk_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), risk_col),
            ("TOPPADDING",    (0,0),(-1,-1), 10),
            ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ]))
        story += [risk_tbl, sp(0.6)]

        counts = ctx["severity_counts"]
        stats = Table(
            [["Hosts Found", "Total Findings", "Critical", "High", "Medium", "Low"],
             [str(ctx["total_hosts"]), str(ctx["total_findings"]),
              str(counts["Critical"]), str(counts["High"]),
              str(counts["Medium"]),   str(counts["Low"])]],
            colWidths=[2.83*cm]*6
        )
        stats.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), NAVY),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("FONTNAME",      (0,0),(-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 9),
            ("FONTSIZE",      (0,1),(-1,1), 16),
            ("ALIGN",         (0,0),(-1,-1), "CENTER"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [LBLUE]),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ("TEXTCOLOR",     (2,1),(2,1), CRIT),
            ("TEXTCOLOR",     (3,1),(3,1), HIGH),
            ("TEXTCOLOR",     (4,1),(4,1), MED),
            ("TEXTCOLOR",     (5,1),(5,1), LOW_C),
        ]))
        story += [stats, sp(0.5),
                  Paragraph("FUPRE Final Year Project | Obeh Emmanuel Onoriode (COS/9581/2022)", SM),
                  PageBreak()]

        # ── PLAIN ENGLISH GUIDE ────────────────────────────────────────────
        story += [Paragraph("What This Report Means", H1), hr(), sp(0.2),
                  Paragraph("This report was generated by CyberScan Pro after scanning <b>" + ctx['target'] + "</b>. It identifies security weaknesses that could be exploited by attackers. <b>You do not need to be a technical expert to understand this report.</b> Every finding includes a plain English explanation of what the problem is, what could happen if exploited, and exactly how to fix it.", BD), sp(0.3)]

        guide = Table([
            ["CRITICAL\n🚨 Fix in 24h", "HIGH\n🔴 Fix in 7 days", "MEDIUM\n🟠 Fix in 30 days", "LOW\n🔵 Fix when possible"],
            ["Attackers can fully\ncompromise the system\nor steal all data",
             "Significant damage\nor data breach likely",
             "Moderate risk,\nspecific conditions\nrequired to exploit",
             "Minor risk,\nlimited direct\nimpact"]
        ], colWidths=[4.25*cm]*4)
        guide.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(0,1), colors.HexColor("#fff0f0")),
            ("BACKGROUND",    (1,0),(1,1), colors.HexColor("#fff5f0")),
            ("BACKGROUND",    (2,0),(2,1), colors.HexColor("#fffbf0")),
            ("BACKGROUND",    (3,0),(3,1), colors.HexColor("#f0f6ff")),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("ALIGN",         (0,0),(-1,-1), "CENTER"),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#DDDDDD")),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        story += [guide, PageBreak()]

        # ── EXECUTIVE SUMMARY ──────────────────────────────────────────────
        story += [Paragraph("Executive Summary", H1), hr(), sp(0.2)]
        summ = (f"An automated vulnerability assessment was conducted against <b>{ctx['target']}</b> on {ctx['generated_at']}. "
                f"The scan discovered <b>{ctx['total_hosts']}</b> live host(s) with <b>{ctx['total_findings']}</b> security findings. "
                f"The overall risk is rated <b>{risk}</b>. ")
        if counts["Critical"] > 0:
            summ += f"<b>{counts['Critical']} CRITICAL issue(s) require immediate action within 24 hours.</b> "
        if counts["High"] > 0:
            summ += f"{counts['High']} HIGH severity issue(s) should be resolved within 7 days. "
        if ctx["total_findings"] == 0:
            summ += "No vulnerabilities were detected — the target appears well-secured against the tested attack vectors."
        story += [Paragraph(summ, BD), PageBreak()]

        # ── METHODOLOGY ────────────────────────────────────────────────────
        story += [Paragraph("Scan Methodology", H1), hr(), sp(0.2)]
        mdata = [["Phase", "What Was Done", "What We Looked For"]] + \
                [[m[0], m[1], m[2]] for m in ctx["methodology"]]
        mt = Table(mdata, colWidths=[4*cm, 6.5*cm, 6.5*cm])
        mt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), NAVY),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LBLUE]),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#CCCCCC")),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))
        story += [mt, PageBreak()]

        # ── HOSTS ──────────────────────────────────────────────────────────
        if ctx["hosts"]:
            story += [Paragraph("Discovered Hosts and Open Services", H1), hr(), sp(0.2),
                      Paragraph("The following hosts and open ports were discovered. Each open port represents a service accessible from the internet.", BD)]
            for host in ctx["hosts"]:
                story.append(Paragraph(f"<b>{host['ip']}</b> — {host.get('hostname','N/A')} — OS: {host.get('os','Unknown')}", H2))
                if host.get("ports"):
                    pd = [["Port", "Service", "Version", "Security Note"]]
                    for p in host["ports"]:
                        port = p.get("port", 0)
                        note = {22:"Ensure key-based auth, disable root login",
                                21:"⚠️ FTP unencrypted — use SFTP instead",
                                23:"🚨 Telnet unencrypted — disable immediately",
                                80:"Redirect all traffic to HTTPS (port 443)",
                                443:"Ensure TLS 1.2+ only, disable old SSL",
                                3306:"⚠️ MySQL publicly exposed — restrict by firewall",
                                3389:"🚨 RDP exposed — restrict to specific IPs only",
                                6379:"🚨 Redis exposed — verify authentication enabled",
                               }.get(port, "Verify this port needs public access")
                        pd.append([f"{port}/{p.get('protocol','tcp')}",
                                   p.get("service",""), str(p.get("version",""))[:30], note])
                    pt = Table(pd, colWidths=[2*cm,2.5*cm,4.5*cm,8*cm])
                    pt.setStyle(TableStyle([
                        ("BACKGROUND",    (0,0),(-1,0), NAVY),
                        ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
                        ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
                        ("FONTSIZE",      (0,0),(-1,-1), 7.5),
                        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LBLUE]),
                        ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#CCCCCC")),
                        ("TOPPADDING",    (0,0),(-1,-1), 4),
                        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                        ("VALIGN",        (0,0),(-1,-1), "TOP"),
                    ]))
                    story.append(pt)
                story.append(sp(0.4))
            story.append(PageBreak())

        # ── WEB FINDINGS ───────────────────────────────────────────────────
        if ctx["web_findings"]:
            story += [Paragraph("Web Application Security Findings", H1), hr(), sp(0.2),
                      Paragraph("Each finding below includes a plain English explanation — what the problem is, what an attacker could do with it, and exactly how to fix it.", BD), sp(0.3)]

            for i, f in enumerate(ctx["web_findings"], 1):
                sev = f.get("severity","Low")
                sc  = SEV_C.get(sev, NONE_C)

                block = []
                # Header
                hdr = Table([[
                    Paragraph(f"<b>{i}. {f.get('vuln_type','')}</b>",
                              S("FH", fontSize=10, textColor=colors.HexColor("#111"),
                                fontName="Helvetica-Bold")),
                    Paragraph(sev, S("SV", fontSize=9, textColor=sc,
                                     fontName="Helvetica-Bold", alignment=1))
                ]], colWidths=[14*cm, 3*cm])
                hdr.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#f8f9fa")),
                    ("TOPPADDING",    (0,0),(-1,-1), 8),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 8),
                    ("LEFTPADDING",   (0,0),(0,-1), 10),
                    ("LINEBELOW",     (0,0),(-1,0), 2, sc),
                ]))
                block.append(hdr)

                # Plain English 2x2 grid
                pe = Table([
                    [Paragraph("<b>🔍 What is this vulnerability?</b>", LB),
                     Paragraph("<b>💡 What does it mean for "+ctx['target']+"?</b>", LB)],
                    [Paragraph(f.get("plain_what",""), PE),
                     Paragraph(f.get("plain_means",""), PE)],
                    [Paragraph("<b>💥 What could an attacker do?</b>", LB),
                     Paragraph("<b>🔧 How to fix it</b>", LB)],
                    [Paragraph(f.get("plain_impact",""), PE),
                     Paragraph(f.get("plain_fix","") + (f"\n\n⏱️ {f.get('plain_difficulty','')}" if f.get("plain_difficulty") else ""), PE)],
                ], colWidths=[8.5*cm, 8.5*cm])
                pe.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#f0f8ff")),
                    ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#dde8f0")),
                    ("TOPPADDING",    (0,0),(-1,-1), 6),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                    ("LEFTPADDING",   (0,0),(-1,-1), 8),
                    ("VALIGN",        (0,0),(-1,-1), "TOP"),
                    ("LINEAFTER",     (0,0),(0,-1), 0.5, colors.HexColor("#c0d8ee")),
                ]))
                block.append(pe)

                # Technical details
                td = Table([
                    [Paragraph("<b>Technical Details (for developers)</b>", LB), ""],
                    ["URL:",       str(f.get("url",""))[:90]],
                    ["Evidence:", str(f.get("evidence","N/A"))[:90]],
                ], colWidths=[3*cm, 14*cm])
                td.setStyle(TableStyle([
                    ("FONTSIZE",      (0,0),(-1,-1), 7.5),
                    ("FONTNAME",      (0,1),(0,-1), "Helvetica-Bold"),
                    ("TEXTCOLOR",     (0,1),(0,-1), colors.grey),
                    ("GRID",          (0,1),(-1,-1), 0.3, colors.HexColor("#EEEEEE")),
                    ("TOPPADDING",    (0,0),(-1,-1), 4),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                    ("LEFTPADDING",   (0,0),(-1,-1), 6),
                    ("SPAN",          (0,0),(-1,0)),
                ]))
                block.append(td)
                block.append(sp(0.4))
                story.append(KeepTogether(block))
            story.append(PageBreak())

        # ── CVE FINDINGS ───────────────────────────────────────────────────
        if ctx["cve_findings"]:
            story += [Paragraph("Known Software Vulnerabilities (CVEs)", H1), hr(), sp(0.2),
                      Paragraph("These are publicly documented security flaws found in software running on <b>"+ctx['target']+"</b>. Because they are publicly known, automated hacking tools actively scan the internet looking for servers running these versions.", BD),
                      Paragraph("⚠️ Automated attack tools scan for these vulnerabilities 24/7. Update the affected software immediately.", S("W", fontSize=9, textColor=CRIT, fontName="Helvetica-Bold", spaceBefore=6, spaceAfter=10)), sp(0.2)]

            cve_data = [["CVE ID", "Host", "Port", "Service", "CVSS", "Severity"]]
            for f in ctx["cve_findings"]:
                cve_data.append([f.get("cve_id",""), f.get("host_ip",""),
                                  str(f.get("port","")), str(f.get("service",""))[:20],
                                  str(f.get("cvss_score","")), f.get("severity","")])
            ct = Table(cve_data, colWidths=[3.5*cm,3*cm,1.5*cm,3.5*cm,1.5*cm,4*cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), NAVY),
                ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
                ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0),(-1,-1), 8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LBLUE]),
                ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#CCCCCC")),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ]))
            story += [ct, sp(0.4)]

            for f in ctx["cve_findings"]:
                score = float(f.get("cvss_score") or 0)
                if score >= 9.0:   danger = "EXTREMELY DANGEROUS — attacker can likely take full control of the system."
                elif score >= 7.0: danger = "HIGHLY DANGEROUS — can lead to significant data theft or system compromise."
                elif score >= 4.0: danger = "MODERATELY DANGEROUS — exploitation requires specific conditions but can lead to a breach."
                else:              danger = "LOW RISK — limited direct impact but should still be patched."

                sev = f.get("severity","Low")
                sc  = SEV_C.get(sev, NONE_C)
                story += [
                    Paragraph(f"<b>{f.get('cve_id','')} — CVSS {f.get('cvss_score','')}/10 ({sev})</b>",
                              S("CH", fontSize=9, textColor=sc, fontName="Helvetica-Bold", spaceBefore=10)),
                    Paragraph(f"<b>Danger level:</b> {danger}", PE),
                    Paragraph(f"<b>Description:</b> {f.get('description','See NVD for details.')[:250]}", PE),
                    Paragraph(f"<b>Fix:</b> Update <b>{f.get('service','')}</b> to the latest version. Visit nvd.nist.gov and search for <b>{f.get('cve_id','')}</b> for specific patch information.", PE),
                    sp(0.2)
                ]
            story.append(PageBreak())

        # ── ACTION PLAN ────────────────────────────────────────────────────
        story += [Paragraph("Your Action Plan — What To Do Next", H1), hr(), sp(0.2),
                  Paragraph("Address these security issues in the following order. Start at the top and work down:", BD), sp(0.2)]

        if ctx["all_findings"]:
            ap = [["#", "Issue", "Severity", "Action Required"]]
            for i, f in enumerate(ctx["all_findings"][:10], 1):
                ap.append([str(i),
                           f.get("vuln_type","")[:40],
                           f.get("severity",""),
                           f.get("recommendation","Fix this issue.")[:70]])
            apt = Table(ap, colWidths=[0.8*cm, 6*cm, 2.5*cm, 7.7*cm])
            apt.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), NAVY),
                ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
                ("FONTNAME",      (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0),(-1,-1), 8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LBLUE]),
                ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#CCCCCC")),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ]))
            story.append(apt)
        else:
            story.append(Paragraph("✅ No immediate actions required. Re-scan periodically to detect new vulnerabilities.", BD))

        # ── FOOTER ─────────────────────────────────────────────────────────
        story += [sp(1), hr(), sp(0.2),
                  Paragraph(f"CyberScan Pro v1.0.0 | FUPRE Final Year Project | Obeh Emmanuel Onoriode (COS/9581/2022) | {ctx['generated_at']} | ⚠ This report is confidential. Authorized use only.", SM)]

        doc.build(story)
        logger.info(f"PDF report: {path}")
