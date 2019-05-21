from flask import (abort, flash, redirect, render_template, request,
                   session, url_for)
import requests

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

from portal import app, database
from portal.decorators import authenticated
from portal.utils import (load_portal_client, get_portal_tokens,
                          get_safe_redirect)

# Use these four lines on container
import sys
sys.path.insert(0, '/etc/ciconnect/secrets')

try:
    f = open("/etc/slate/secrets/slate_api_token.txt", "r")
    g = open("slate_api_endpoint.txt", "r")
except:
    # Use these two lines below on local
    f = open("/Users/JeremyVan/Documents/Programming/UChicago/CI_Connect/secrets/ciconnect_api_token.txt", "r")
    g = open("/Users/JeremyVan/Documents/Programming/UChicago/CI_Connect/secrets/ciconnect_api_endpoint.txt", "r")

ciconnect_api_token = f.read().split()[0]
ciconnect_api_endpoint = g.read().split()[0]


@app.route('/', methods=['GET'])
def home():
    """Home page - play with it if you must!"""
    return render_template('home.html')


@app.route('/projects', methods=['GET'])
def projects():
    """OSG Connect Projects"""
    return render_template('projects.html')


@app.route('/projects/new', methods=['GET', 'POST'])
# @authenticated
def create_project():
    """Create Projects"""
    if request.method == 'GET':
        return render_template('projects_create.html')


@app.route('/signup', methods=['GET'])
def signup():
    """Send the user to Globus Auth with signup=1."""
    return redirect(url_for('authcallback', signup=1))


@app.route('/login', methods=['GET'])
def login():
    """Send the user to Globus Auth."""
    return redirect(url_for('authcallback'))


@app.route('/logout', methods=['GET'])
@authenticated
def logout():
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    client = load_portal_client()

    # Revoke the tokens with Globus Auth
    for token, token_type in (
            (token_info[ty], ty)
            # get all of the token info dicts
            for token_info in session['tokens'].values()
            # cross product with the set of token types
            for ty in ('access_token', 'refresh_token')
            # only where the relevant token is actually present
            if token_info[ty] is not None):
        client.oauth2_revoke_token(
            token, additional_params={'token_type_hint': token_type})

    # Destroy the session state
    session.clear()

    redirect_uri = url_for('home', _external=True)

    ga_logout_url = []
    ga_logout_url.append(app.config['GLOBUS_AUTH_LOGOUT_URI'])
    ga_logout_url.append('?client={}'.format(app.config['PORTAL_CLIENT_ID']))
    ga_logout_url.append('&redirect_uri={}'.format(redirect_uri))
    ga_logout_url.append('&redirect_name=Globus Sample Data Portal')

    # Redirect the user to the Globus Auth logout page
    return redirect(''.join(ga_logout_url))


@app.route('/profile', methods=['GET', 'POST'])
@authenticated
def profile():
    """User profile information. Assocated with a Globus Auth identity."""
    if request.method == 'GET':
        identity_id = session.get('primary_identity')
        profile = database.load_profile(identity_id)

        if profile:
            name, email, institution = profile

            session['name'] = name
            session['email'] = email
            session['institution'] = institution
        else:
            flash(
                'Please complete any missing profile fields and press Save.', 'warning')

        if request.args.get('next'):
            session['next'] = get_safe_redirect()

        return render_template('profile.html')
    elif request.method == 'POST':
        name = session['name'] = request.form['name']
        email = session['email'] = request.form['email']
        institution = session['institution'] = request.form['institution']

        database.save_profile(identity_id=session['primary_identity'],
                              name=name,
                              email=email,
                              institution=institution)

        flash('Thank you! Your profile has been successfully updated.', 'success')

        if 'next' in session:
            redirect_to = session['next']
            session.pop('next')
        else:
            redirect_to = url_for('profile')

        return redirect(redirect_to)


@app.route('/authcallback', methods=['GET'])
def authcallback():
    """Handles the interaction with Globus Auth."""
    # If we're coming back from Globus Auth in an error state, the error
    # will be in the "error" query string parameter.
    if 'error' in request.args:
        flash("You could not be logged into the portal: " +
              request.args.get('error_description', request.args['error']), 'warning')
        return redirect(url_for('home'))

    # Set up our Globus Auth/OAuth2 state
    redirect_uri = url_for('authcallback', _external=True)

    client = load_portal_client()
    client.oauth2_start_flow(redirect_uri, refresh_tokens=True)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    if 'code' not in request.args:
        additional_authorize_params = (
            {'signup': 1} if request.args.get('signup') else {})

        auth_uri = client.oauth2_get_authorize_url(
            additional_params=additional_authorize_params)

        return redirect(auth_uri)
    else:
        # If we do have a "code" param, we're coming back from Globus Auth
        # and can start the process of exchanging an auth code for a token.
        code = request.args.get('code')
        tokens = client.oauth2_exchange_code_for_tokens(code)

        id_token = tokens.decode_id_token(client)
        session.update(
            tokens=tokens.by_resource_server,
            is_authenticated=True,
            name=id_token.get('name', ''),
            email=id_token.get('email', ''),
            institution=id_token.get('institution', ''),
            primary_username=id_token.get('preferred_username'),
            primary_identity=id_token.get('sub'),
        )

        profile = database.load_profile(session['primary_identity'])

        if profile:
            name, email, institution = profile

            session['name'] = name
            session['email'] = email
            session['institution'] = institution
        else:
            return redirect(url_for('profile',
                            next=url_for('profile')))

        return redirect(url_for('profile'))
