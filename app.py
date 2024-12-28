import os
import requests
from flask import Flask, request, redirect, render_template, session, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = Flask(__name__)

# Set the Flask secret key for session management
app.secret_key = "your_secret_key"

# Configure the base path for SAML
PROJECT_DIRPATH = os.getcwd()  # Use current working directory as base
SAML_FOLDER = os.path.join(PROJECT_DIRPATH, 'saml')

def prepare_request(flask_request):
    """Prepare the request object for SAML."""
    return {
        "https": "on" if flask_request.scheme == "https" else "off",
        "http_host": flask_request.host,
        "script_name": flask_request.path,
        "server_port": flask_request.environ.get("SERVER_PORT", "443"),
        "get_data": flask_request.args.copy(),
        "post_data": flask_request.form.copy(),
    }

@app.route("/adfs", methods=["GET", "POST"])
def adfs_route():
    """ADFS SSO/SLO entry point and processing."""
    req = prepare_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_FOLDER)

    error = None

    # Handle Single Sign-On (SSO)
    if "sso" in request.args:
        return redirect(auth.login())

    # Handle Assertion Consumer Service (ACS) callback
    elif "acs" in request.args:
        auth.process_response()
        not_auth_warn = not auth.is_authenticated()
        if not auth.get_errors():
            # Store SAML user data in session
            session["samlUserdata"] = auth.get_attributes()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if "RelayState" in request.form and self_url != request.form["RelayState"]:
                return redirect(auth.redirect_to(request.form["RelayState"]))
        elif auth.get_settings().is_debug_active():
            error = auth.get_last_error_reason()

    # Handle Single Logout (SLO)
    elif "slo" in request.args:
        session.clear()
        return redirect(url_for("adfs_route"))

    # Process logged-in user data if available
    if "samlUserdata" in session:
        attributes = session["samlUserdata"]
        user_id = attributes.get("USER_ID", [None])[0]
        if user_id:
            # Example of sending a request to Resource X
            resourcex_data = requests.get(f"https://resourcex.com/{user_id}")
            return render_template("data.html", data=resourcex_data.json())

    return render_template("index.html", error=error)

if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)
