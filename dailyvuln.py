import os
import smtplib
import requests
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
 

DAYS_BACK = 1
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.hostinger.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")


 
def fetch_nvd():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=DAYS_BACK)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=30)
    r.raise_for_status()
    out = []
    for item in r.json().get("vulnerabilities", []):
        cve = item["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
 
        produtos = set()
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    partes = criteria.split(":")
                    if len(partes) > 4:
                        vendor, produto = partes[3], partes[4]
                        produtos.add(f"{vendor} {produto}")
        tecnologia = ", ".join(sorted(produtos)) or "N/A"
 
        out.append(
            f"<b>{cve['id']}</b><br>"
            f"<span style='color:#555;'>Tecnologia:</span> {tecnologia}<br>"
            f"<span style='color:#555;'>Descrição:</span> {desc[:200]}"
        )
    return out
 
 
def fetch_npm():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=DAYS_BACK)
    params = {
        "ecosystem": "npm",
        "published": f"{start.strftime('%Y-%m-%d')}..{end.strftime('%Y-%m-%d')}",
        "per_page": 100,
    }
    r = requests.get("https://api.github.com/advisories", params=params,
                      headers={"Accept": "application/vnd.github+json"}, timeout=30)
    r.raise_for_status()
    out = []
    for adv in r.json():
        pkgs = ", ".join(v.get("package", {}).get("name", "?") for v in adv.get("vulnerabilities", []))
        out.append(
            f"<b>{adv.get('ghsa_id')}</b><br>"
            f"<span style='color:#555;'>Pacote(s):</span> {pkgs}<br>"
            f"<span style='color:#555;'>Descrição:</span> {adv.get('summary', '')[:200]}"
        )
    return out
 
 
def build_report_html(nvd, npm):
    def bloco(titulo, itens, cor):
        if not itens:
            linhas = "<p style='color:#888;'>Nenhum item encontrado.</p>"
        else:
            linhas = ""
            for item in itens:
                linhas += f"""
                <div style="border-left:4px solid {cor}; padding:8px 14px; margin-bottom:10px; background:#f9f9f9;">
                    {item}
                </div>"""
        return f"""
        <h2 style="color:{cor}; border-bottom:2px solid {cor}; padding-bottom:4px;">{titulo} ({len(itens)})</h2>
        {linhas}
        """
 
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; color:#222; max-width:700px; margin:auto;">
        <h1 style="color:#111;">🛡️ Relatório de Vulnerabilidades</h1>
        <p>Período analisado: últimos <b>{DAYS_BACK} dias</b></p>
        {bloco("NVD - CVEs Gerais", nvd, "#c0392b")}
        {bloco("NPM - GitHub Advisory", npm, "#2980b9")}
        <hr>
        <p style="font-size:12px; color:#999;">Relatório gerado automaticamente.</p>
    </body>
    </html>
    """
 
 
def send_email(subject, html_body):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_TO
    msg.attach(MIMEText(html_body, "html", "utf-8"))
 
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [EMAIL_TO], msg.as_string())
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [EMAIL_TO], msg.as_string())
 
 
def main():
    nvd = fetch_nvd()
    npm = fetch_npm()
 
    html = build_report_html(nvd, npm)
    print(f"NVD: {len(nvd)} | NPM: {len(npm)}")
    send_email(f"Relatório de Vulnerabilidades ({len(nvd)+len(npm)})", html)
 
 
if __name__ == "__main__":
    main()
 
