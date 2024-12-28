$projectPath = "C:\Users\adfsSVC\Documents\adfs-sso"

# Create project folder
if (!(Test-Path $projectPath)) {
    New-Item -Path $projectPath -ItemType Directory
}

# Create saml folder
$samlPath = Join-Path $projectPath "saml"
if (!(Test-Path $samlPath)) {
    New-Item -Path $samlPath -ItemType Directory
}

# Create templates folder
$templatesPath = Join-Path $projectPath "templates"
if (!(Test-Path $templatesPath)) {
    New-Item -Path $templatesPath -ItemType Directory
}

# Create app.py
$appCode = @"
from flask import Flask, request, redirect, render_template, make_response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

import os

app = Flask(__name__)

# Configuration for SAML
SAML_FOLDER = os.path.join(os.getcwd(), "saml")  # Store SAML settings and certs in the 'saml' folder

def init_saml_auth(req):
    """Initialize SAML authentication object."""
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_FOLDER)
    return auth

def prepare_flask_request(request):
    """Prepare request object for SAML."""
    url_data = request.url.split("?")
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "server_port": request.environ.get("SERVER_PORT", "443"),
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }

@app.route("/")
def index():
    """Home page."""
    return render_template("index.html")

@app.route("/sso")
def sso():
    """Start SSO process."""
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route("/sso/acs", methods=["POST"])
def acs():
    """Assertion Consumer Service (ACS) endpoint."""
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        return f"Error during SAML authentication: {errors}", 400

    if not auth.is_authenticated():
        return "User not authenticated", 403

    user_data = {
        "name_id": auth.get_nameid(),
        "session_index": auth.get_session_index(),
        "attributes": auth.get_attributes(),
    }
    return render_template("dashboard.html", user_data=user_data)

@app.route("/sso/logout")
def logout():
    """Logout from the SSO session."""
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.logout())

@app.route("/sso/sls")
def sls():
    """Single Logout Service (SLS) endpoint."""
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_slo()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
"@
Set-Content -Path (Join-Path $projectPath "app.py") -Value $appCode

# Create index.html
$indexHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>SAML SSO Demo</title>
</head>
<body>
    <h1>Welcome to SAML SSO Demo</h1>
    <a href="/sso">Login via SAML SSO</a>
</body>
</html>
"@
Set-Content -Path (Join-Path $templatesPath "index.html") -Value $indexHtml

# Create dashboard.html
$dashboardHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>SAML Dashboard</title>
</head>
<body>
    <h1>Dashboard</h1>
    <p><strong>NameID:</strong> {{ user_data.name_id }}</p>
    <p><strong>Attributes:</strong></p>
    <ul>
        {% for key, value in user_data.attributes.items() %}
            <li>{{ key }}: {{ value[0] }}</li>
        {% endfor %}
    </ul>
    <a href="/sso/logout">Logout</a>
</body>
</html>
"@
Set-Content -Path (Join-Path $templatesPath "dashboard.html") -Value $dashboardHtml

# Create saml/settings.json
$samlSettings = @"
{
    "sp": {
        "entityId": "http://localhost:5000/metadata/",
        "assertionConsumerService": {
            "url": "http://localhost:5000/sso/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": "http://localhost:5000/sso/sls",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "",
        "privateKey": ""
    },
    "idp": {
        "entityId": "https://WIN-VPPBLHAA841.jags.local/adfs/services/trust",
        "singleSignOnService": {
            "url": "https://WIN-VPPBLHAA841.jags.local/adfs/ls/",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": "https://WIN-VPPBLHAA841.jags.local/adfs/ls/",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "-----BEGIN CERTIFICATE-----\n...your AD FS certificate...\n-----END CERTIFICATE-----"
    }
}
"@
Set-Content -Path (Join-Path $samlPath "settings.json") -Value $samlSettings

Write-Host "Project files created successfully at $projectPath"
