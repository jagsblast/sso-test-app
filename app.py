from flask import Flask, request, redirect, render_template, Response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
import os
import base64
from xml.dom.minidom import parseString

app = Flask(__name__)

# Configuration for SAML
SAML_FOLDER = os.path.join(os.getcwd(), "saml")

def init_saml_auth(req):
    """Initialize SAML authentication object."""
    return OneLogin_Saml2_Auth(req, custom_base_path=SAML_FOLDER)

def prepare_flask_request(request):
    """Prepare request object for SAML."""
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "server_port": request.environ.get("SERVER_PORT", "443"),
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }

@app.route("/metadata")
def metadata():
    """Serve SAML metadata."""
    saml_settings = OneLogin_Saml2_Settings(
        {}, custom_base_path=SAML_FOLDER, sp_validation_only=True
    )
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) > 0:
        return f"Metadata validation errors: {errors}", 500

    return Response(metadata, content_type="application/xml")

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

    # Extract and decode the SAML response
    saml_response = request.form.get('SAMLResponse')
    decoded_response = ""
    try:
        if saml_response:
            decoded_response = base64.b64decode(saml_response).decode('utf-8')
    except Exception as e:
        return f"Failed to decode SAMLResponse: {e}", 400

    # Process the response
    auth.process_response()
    errors = auth.get_errors()
    error_reason = auth.get_last_error_reason()

    # Gather diagnostics
    diagnostics = {
        "Raw SAMLResponse (Base64)": saml_response or "No SAMLResponse provided",
        "Decoded SAMLResponse (XML)": decoded_response or "Failed to decode SAMLResponse",
        "SAML Errors": errors or "No errors",
        "Last Error Reason": error_reason or "No detailed error reason",
        "Is Authenticated": auth.is_authenticated(),
        "NameID": auth.get_nameid() or "None",
        "Session Index": auth.get_session_index() or "None",
        "Attributes": auth.get_attributes() or "None",
    }

    # Format diagnostics as HTML
    html_output = "<h1>SAML Diagnostics</h1><ul>"
    for key, value in diagnostics.items():
        html_output += f"<li><strong>{key}:</strong><pre>{value}</pre></li>"
    html_output += "</ul>"

    # Return diagnostics as a response
    return html_output, 400 if errors else 200

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
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)
