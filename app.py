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

    # Extract and log raw SAMLResponse
    saml_response = request.form.get('SAMLResponse')
    if saml_response:
        print("Raw SAMLResponse (Base64):")
        print(saml_response)

        try:
            decoded_response = base64.b64decode(saml_response).decode('utf-8')
            pretty_xml = parseString(decoded_response).toprettyxml()
            print("Decoded SAMLResponse (XML):")
            print(pretty_xml)
        except Exception as e:
            print(f"Failed to decode SAMLResponse: {e}")

    # Process the SAML response
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        error_reason = auth.get_last_error_reason()
        print(f"SAML Errors: {errors}")
        print(f"Detailed Error Reason: {error_reason}")
        return (
            f"<h1>Error during SAML authentication</h1>"
            f"<p>Errors: {errors}</p>"
            f"<p>Reason: {error_reason}</p>",
            400
        )

    if not auth.is_authenticated():
        print("Authentication failed: User not authenticated")
        return (
            "<h1>User not authenticated</h1>"
            "<p>Please check the SAML response for issues.</p>",
            403
        )

    user_data = {
        "name_id": auth.get_nameid(),
        "session_index": auth.get_session_index(),
        "attributes": auth.get_attributes(),
    }
    print("User authenticated successfully:")
    print(f"User data: {user_data}")
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
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)
