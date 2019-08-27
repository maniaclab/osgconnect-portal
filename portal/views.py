from flask import (abort, flash, redirect, render_template, request,
                   session, url_for, Markup)
import requests, traceback, json, time

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

from portal import app
from portal.decorators import authenticated
from portal.utils import (load_portal_client, get_portal_tokens,
                          get_safe_redirect)

# Use these four lines on container
import sys
sys.path.insert(0, '/etc/ci-connect/secrets')

try:
    f = open("/etc/ci-connect/secrets/ciconnect_api_token.txt", "r")
    g = open("/etc/ci-connect/secrets/ciconnect_api_endpoint.txt", "r")
except:
    # Use these two lines below on local
    f = open("/Users/JeremyVan/Documents/Programming/UChicago/CI_Connect/secrets/ciconnect_api_token.txt", "r")
    g = open("/Users/JeremyVan/Documents/Programming/UChicago/CI_Connect/secrets/ciconnect_api_endpoint.txt", "r")

ciconnect_api_token = f.read().split()[0]
ciconnect_api_endpoint = g.read().split()[0]

# Create a custom error handler for Exceptions
@app.errorhandler(Exception)
def exception_occurred(e):
    trace = traceback.format_tb(sys.exc_info()[2])
    app.logger.error("{0} Traceback occurred:\n".format(time.ctime()) +
                     "{0}\nTraceback completed".format("n".join(trace)))
    trace = "<br>".join(trace)
    trace.replace('\n', '<br>')
    return render_template('error.html', exception=trace,
                           debug=app.config['DEBUG'])

@app.route('/error', methods=['GET'])
def errorpage():
    if request.method == 'GET':
        return render_template('error.html')


@app.errorhandler(404)
def not_found(e):
  return render_template("404.html")


@app.route('/', methods=['GET'])
def home():
    """Home page - play with it if you must!"""
    return render_template('home.html')


@app.route('/groups', methods=['GET'])
def groups():
    """OSG Connect groups"""
    if request.method == 'GET':
        query = {'token': ciconnect_api_token}
        groups = requests.get(ciconnect_api_endpoint + '/v1alpha1/groups', params=query)
        groups = groups.json()['groups']
        return render_template('groups.html', groups=groups)


@app.route('/groups/new', methods=['GET', 'POST'])
@authenticated
def create_group():
    """Create groups"""
    query = {'token': session['access_token']}
    if request.method == 'GET':
        sciences = requests.get(ciconnect_api_endpoint + '/v1alpha1/fields_of_science')
        sciences = sciences.json()['fields_of_science']
        return render_template('groups_create.html', sciences=sciences)
    elif request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        field_of_science = request.form['field_of_science']
        description = request.form['description']

        put_group = {"apiVersion": 'v1alpha1', "kind": "Group",
                        'metadata': {'name': name,
                                    'field_of_science': field_of_science,
                                    'email': email, 'phone': phone,
                                    'description': description}}
        create_group = requests.put(ciconnect_api_endpoint + '/v1alpha1/groups/root/subgroups/' + name, params=query, json=put_group)
        if create_group.status_code == requests.codes.ok:
            flash("Successfully created group", 'success')
            return redirect(url_for('groups'))
        else:
            err_message = create_group.json()['message']
            flash('Failed to create group: {}'.format(err_message), 'warning')
            return redirect(url_for('groups'))


@app.route('/groups/<group_name>', methods=['GET', 'POST'])
@authenticated
def view_group(group_name):
    """Detailed view of specific groups"""
    query = {'token': ciconnect_api_token,
             'globus_id': session['primary_identity']}

    user = requests.get(ciconnect_api_endpoint + '/v1alpha1/find_user', params=query)
    user = user.json()
    unix_name = user['metadata']['unix_name']

    if request.method == 'GET':
        group = requests.get(ciconnect_api_endpoint + '/v1alpha1/groups/' + group_name, params=query)
        group = group.json()['metadata']
        group_name = group['name']
        # Remove 'root' and join group naming
        display_name = group['name'].split('.')[1:]
        display_name = '-'.join(display_name)
        # Get User's Group Status
        user_status = requests.get(
                        ciconnect_api_endpoint + '/v1alpha1/groups/' +
                        group_name + '/members/' + unix_name, params=query)
        user_status = user_status.json()['membership']['state']
        # print("USER STATUS: {}".format(user_status))
        subgroups = requests.get(ciconnect_api_endpoint + '/v1alpha1/groups/' + group_name + '/subgroups', params=query)
        subgroups = subgroups.json()['groups']
        subgroups = sorted(subgroups, key=lambda k: k['name'])
        # print(subgroups)

        return render_template('group_profile.html', group=group,
                                group_name=group_name, display_name=display_name,
                                user_status=user_status, subgroups=subgroups)
    elif request.method == 'POST':
        '''Request membership to join group'''
        put_query = {"apiVersion": 'v1alpha1',
                        'group_membership': {'state': 'pending'}}
        user_status = requests.put(
                        ciconnect_api_endpoint + '/v1alpha1/groups/' +
                        group_name + '/members/' + unix_name, params=query, json=put_query)
        # print("UPDATED MEMBERSHIP: {}".format(user_status))
        return redirect(url_for('view_group', group_name=group_name))


@app.route('/groups/<group_name>/delete', methods=['POST'])
@authenticated
def delete_group(group_name):
    if request.method == 'POST':
        token_query = {'token': session['access_token']}

        r = requests.delete(
            ciconnect_api_endpoint + '/v1alpha1/groups/' + group_name, params=token_query)
        print(r)

        if r.status_code == requests.codes.ok:
            flash("Successfully deleted group", 'success')
            return redirect(url_for('groups'))
        else:
            err_message = r.json()['message']
            flash('Failed to delete group: {}'.format(err_message), 'warning')
            return redirect(url_for('view_group', group_name=group_name))


@app.route('/groups/<group_name>/members', methods=['GET', 'POST'])
@authenticated
def view_group_members(group_name):
    """Detailed view of group's members"""
    query = {'token': ciconnect_api_token}
    if request.method == 'GET':
        display_name = '-'.join(group_name.split('.')[1:])
        group_members = requests.get(ciconnect_api_endpoint + '/v1alpha1/groups/' + group_name + '/members', params=query)
        # print(group_members.json())
        memberships = group_members.json()['memberships']
        members = []

        for user in memberships:
            unix_name = user['user_name']
            user_state = user['state']
            user_info = requests.get(ciconnect_api_endpoint + '/v1alpha1/users/' + unix_name, params=query)
            user_info = user_info.json()['metadata']
            members.append((user_info, unix_name, user_state))

        # Get User's Group Status
        user_status = requests.get(
                        ciconnect_api_endpoint + '/v1alpha1/groups/' +
                        group_name + '/members/' + unix_name, params=query)
        user_status = user_status.json()['membership']['state']
        query = {'token': ciconnect_api_token}
        user_super = requests.get(
                        ciconnect_api_endpoint + '/v1alpha1/users/' + unix_name, params=query)
        # print("USER SUPER: {}".format(user_super.json()['metadata']['superuser']))
        try:
            user_super = user_super.json()['metadata']['superuser']
        except:
            user_super = False

        return render_template('group_profile_members.html',
                                group_members=members, group_name=group_name,
                                display_name=display_name, user_status=user_status,
                                user_super=user_super)

@app.route('/groups/<group_name>/add_group_member/<unix_name>', methods=['POST'])
@authenticated
def add_group_member(group_name, unix_name):
    if request.method == 'POST':
        query = {'token': session['access_token']}

        put_query = {"apiVersion": 'v1alpha1',
                        'group_membership': {'state': 'active'}}
        user_status = requests.put(
                        ciconnect_api_endpoint + '/v1alpha1/groups/' +
                        group_name + '/members/' + unix_name, params=query, json=put_query)
        # print("UPDATED MEMBERSHIP: {}".format(user_status))

        if user_status.status_code == requests.codes.ok:
            flash("Successfully added member to group", 'success')
            return redirect(url_for('view_group_members', group_name=group_name))
        else:
            err_message = user_status.json()['message']
            flash('Failed to add member to group: {}'.format(err_message), 'warning')
            return redirect(url_for('view_group_members', group_name=group_name))


@app.route('/groups/<group_name>/delete_group_member/<unix_name>', methods=['POST'])
@authenticated
def remove_group_member(group_name, unix_name):
    if request.method == 'POST':
        query = {'token': session['access_token']}
        remove_user = requests.delete(
                        ciconnect_api_endpoint + '/v1alpha1/groups/' +
                        group_name + '/members/' + unix_name, params=query)
        print("UPDATED remove_user: {}".format(remove_user))

        if remove_user.status_code == requests.codes.ok:
            flash("Successfully removed member from group", 'success')
            return redirect(url_for('view_group_members', group_name=group_name))
        else:
            err_message = remove_user.json()['message']
            flash('Failed to remove member from group: {}'.format(err_message), 'warning')
            return redirect(url_for('view_group_members', group_name=group_name))


@app.route('/groups/<group_name>/admin_group_member/<unix_name>', methods=['POST'])
@authenticated
def admin_group_member(group_name, unix_name):
    if request.method == 'POST':
        query = {'token': session['access_token']}

        put_query = {"apiVersion": 'v1alpha1',
                        'group_membership': {'state': 'admin'}}
        user_status = requests.put(
                        ciconnect_api_endpoint + '/v1alpha1/groups/' +
                        group_name + '/members/' + unix_name, params=query, json=put_query)
        # print("UPDATED MEMBERSHIP: {}".format(user_status))

        if user_status.status_code == requests.codes.ok:
            flash("Successfully updated member to admin", 'success')
            return redirect(url_for('view_group_members', group_name=group_name))
        else:
            err_message = user_status.json()['message']
            flash('Failed make member an admin: {}'.format(err_message), 'warning')
            return redirect(url_for('view_group_members', group_name=group_name))


@app.route('/groups/<group_name>/subgroups', methods=['GET', 'POST'])
@authenticated
def view_group_subgroups(group_name):
    """Detailed view of group's subgroups"""
    query = {'token': ciconnect_api_token}
    if request.method == 'GET':
        display_name = '-'.join(group_name.split('.')[1:])
        subgroups = requests.get(ciconnect_api_endpoint + '/v1alpha1/groups/' + group_name + '/subgroups', params=query)
        subgroups = subgroups.json()['groups']
        # Get User's Group Status
        user_status = requests.get(
                        ciconnect_api_endpoint + '/v1alpha1/groups/' +
                        group_name + '/members/' + session['unix_name'], params=query)

        user_status = user_status.json()['membership']['state']

        subgroup_requests = requests.get(ciconnect_api_endpoint + '/v1alpha1/groups/' + group_name + '/subgroup_requests', params=query)
        print(subgroup_requests.json())

        return render_template('group_profile_subgroups.html',
                                display_name=display_name, subgroups=subgroups,
                                group_name=group_name, user_status=user_status)


@app.route('/groups/<group_name>/subgroups/new', methods=['GET', 'POST'])
@authenticated
def create_subgroup(group_name):
    token_query = {'token': session['access_token']}
    if request.method == 'GET':
        sciences = requests.get(ciconnect_api_endpoint + '/v1alpha1/fields_of_science')
        sciences = sciences.json()['fields_of_science']
        return render_template('groups_create.html', sciences=sciences, group_name=group_name)

    elif request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        field_of_science = request.form['field_of_science']
        description = request.form['description']

        put_query = {"apiVersion": 'v1alpha1',
                        'metadata': {'name': name,
                                    'field_of_science': field_of_science,
                                    'email': email, 'phone': phone,
                                    'description': description}}
        # Request query to create group
        # r = requests.put(
        #     ciconnect_api_endpoint + '/v1alpha1/groups/' + group_name +
        #     '/subgroups/' + name, params=token_query, json=put_query)

        r = requests.put(
            ciconnect_api_endpoint + '/v1alpha1/groups/' + group_name +
            '/subgroup_requests/' + group_name, params=token_query, json=put_query)

        if r.status_code == requests.codes.ok:
            flash("Successfully requested project creation", 'success')
            return redirect(url_for('groups'))
        else:
            err_message = r.json()['message']
            flash('Failed to request project creation: {}'.format(err_message), 'warning')
            return redirect(url_for('view_group', group_name=group_name))


@app.route('/signup', methods=['GET'])
def signup():
    """Send the user to Globus Auth with signup=1."""
    # return redirect(url_for('authcallback', signup=1))
    return render_template('signup.html')


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


@app.route('/profile/new', methods=['GET', 'POST'])
@authenticated
def create_profile():
    identity_id = session.get('primary_identity')
    institution = session.get('institution')
    globus_id = identity_id
    query = {'token': ciconnect_api_token,
             'globus_id': globus_id}

    if request.method == 'GET':
        return render_template('profile_create.html')

    elif request.method == 'POST':
        name = request.form['name']
        unix_name = request.form['unix_name']
        email = request.form['email']
        phone = request.form['phone-number']
        institution = request.form['institution']
        globus_id = session['primary_identity']

        public_key = request.form['sshpubstring']

        superuser = False
        service_account = False
        # Schema and query for adding users to CI Connect DB
        if public_key:
            post_user = {"apiVersion": 'v1alpha1',
                        'metadata': {'globusID': globus_id, 'name': name, 'email': email,
                                     'phone': phone, 'institution': institution,
                                     'public_key': public_key,
                                     'unix_name': unix_name, 'superuser': superuser,
                                     'service_account': service_account}}
        else:
            post_user = {"apiVersion": 'v1alpha1',
                        'metadata': {'globusID': globus_id, 'name': name, 'email': email,
                                     'phone': phone, 'institution': institution,
                                     'unix_name': unix_name, 'superuser': superuser,
                                     'service_account': service_account}}

        print("POSTED: {}".format(post_user))

        r = requests.post(ciconnect_api_endpoint + '/v1alpha1/users', params=query, json=post_user)
        print(r.content)
        r = r.json()['metadata']
        session['access_token'] = r['access_token']
        unix_name = r['unix_name']
        flash(
            'Successfully created your account.', 'success')

        # print("Sesion: {}".format(session))
        # print("Created User: {}".format(r))

        # Auto generate group membership into OSG - eventually change to
        # dynamically choose connect site based on URL
        put_query = {"apiVersion": 'v1alpha1',
                        'group_membership': {'state': 'pending'}}
        user_status = requests.put(
                        ciconnect_api_endpoint +
                        '/v1alpha1/groups/root.osg/members/' + unix_name,
                        params=query, json=put_query)

        # print("UPDATED MEMBERSHIP: {}".format(user_status))

        if 'next' in session:
            redirect_to = session['next']
            session.pop('next')
        else:
            redirect_to = url_for('profile')

        return redirect(url_for('profile'))


@app.route('/profile/edit/<unix_name>', methods=['GET', 'POST'])
@authenticated
def edit_profile(unix_name):
    identity_id = session.get('primary_identity')
    query = {'token': ciconnect_api_token,
             'globus_id': identity_id}
    user = requests.get(
                ciconnect_api_endpoint + '/v1alpha1/find_user', params=query)
    unix_name = user.json()['metadata']['unix_name']

    if request.method == 'GET':
        # Get user info, pass through as args, convert to json and load input fields
        profile = requests.get(
                    ciconnect_api_endpoint + '/v1alpha1/users/' + unix_name, params=query)
        profile = profile.json()['metadata']

        return render_template('profile_edit.html', profile=profile)

    elif request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone-number']
        institution = request.form['institution']
        public_key = request.form['sshpubstring']

        globus_id = session['primary_identity']
        try:
            superuser = request.form['superuser']
            superuser = True
        except:
            superuser = False
        print("SUPERUSER: {}".format(superuser))
        service_account = False
        # Schema and query for adding users to CI Connect DB
        if public_key:
            post_user = {"apiVersion": 'v1alpha1',
                        'metadata': {'name': name, 'email': email,
                                     'phone': phone, 'institution': institution,
                                     'public_key': public_key, 'superuser': superuser}}
        else:
            post_user = {"apiVersion": 'v1alpha1',
                        'metadata': {'name': name, 'email': email,
                                     'phone': phone, 'institution': institution,
                                     'superuser': superuser}}
                                     
        r = requests.put(ciconnect_api_endpoint + '/v1alpha1/users/' + unix_name, params=query, json=post_user)
        print("Updated User: ", r)
        session['unix_name'] = unix_name

        if 'next' in session:
            redirect_to = session['next']
            session.pop('next')
        else:
            redirect_to = url_for('profile')

        return redirect(url_for('profile'))


@app.route('/profile', methods=['GET', 'POST'])
@authenticated
def profile():
    """User profile information. Assocated with a Globus Auth identity."""
    if request.method == 'GET':
        identity_id = session.get('primary_identity')
        query = {'token': ciconnect_api_token,
                 'globus_id': identity_id}

        try:
            user = requests.get(ciconnect_api_endpoint + '/v1alpha1/find_user', params=query)
            user = user.json()
            unix_name = user['metadata']['unix_name']
            user_token = user['metadata']['access_token']

            profile = requests.get(
                        ciconnect_api_endpoint + '/v1alpha1/users/' + unix_name, params=query)
            profile = profile.json()
        except:
            profile = None

        if profile:
            profile = profile['metadata']
            name = profile['name']
            email = profile['email']
            phone = profile['phone']
            institution = profile['institution']
            ssh_pubkey = profile['public_key']
        else:
            flash(
                'Please complete any missing profile fields and press Save.', 'warning')

        if request.args.get('next'):
            session['next'] = get_safe_redirect()
        return render_template('profile.html', profile=profile)

    elif request.method == 'POST':
        name = session['name'] = request.form['name']
        email = session['email'] = request.form['email']
        institution = session['institution'] = request.form['institution']
        globus_id = session['primary_identity']
        phone = request.form['phone-number']
        public_key = request.form['sshpubstring']
        superuser = True
        service_account = False

        # flash('Thank you! Your profile has been successfully updated.', 'success')

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
            institution=id_token.get('organization', ''),
            primary_username=id_token.get('preferred_username'),
            primary_identity=id_token.get('sub'),
        )

        # print("URL ROOT CAME FROM: {}".format(request.url_root))
        globus_id = session['primary_identity']
        query = {'token': ciconnect_api_token,
                 'globus_id': globus_id}
        try:
            r = requests.get(
                ciconnect_api_endpoint + '/v1alpha1/find_user', params=query)
            print("AUTH: {}".format(r.json()))
            user_info = r.json()
            user_access_token = user_info['metadata']['access_token']
            unix_name = user_info['metadata']['unix_name']
            profile = requests.get(
                        ciconnect_api_endpoint + '/v1alpha1/users/' + unix_name, params=query)
            profile = profile.json()
            # print("PROFILE: {}".format(profile))
        except:
            profile = None

        if profile:
            profile = profile['metadata']
            print(profile)
            session['name'] = profile['name']
            session['email'] = profile['email']
            session['institution'] = profile['institution']
            session['access_token'] = profile['access_token']
            session['unix_name'] = profile['unix_name']
            session['url_root'] = request.url_root
        else:
            print("NO PROFILE")
            session['url_root'] = request.url_root
            return redirect(url_for('create_profile',
                            next=url_for('profile')))

        return redirect(url_for('profile'))
