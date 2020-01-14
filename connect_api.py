from flask import request, session
import requests
from portal import app
import json

ciconnect_api_token = app.config['CONNECT_API_TOKEN']
ciconnect_api_endpoint = app.config['CONNECT_API_ENDPOINT']


def connect_name(group_name):
    connect_name = '.'.join(group_name.split('.')[:2])

    return connect_name


def list_connect_admins(group_name):
    """
    Return list of admins of connect group
    Return list of nested dictionaries with state, user_name, and state_set_by
    """
    query = {'token': ciconnect_api_token}
    group_members = requests.get(
            ciconnect_api_endpoint + '/v1alpha1/groups/'
            + connect_name(group_name) + '/members', params=query)
    memberships = group_members.json()['memberships']
    memberships = [member for member in memberships if member['state'] == 'admin']

    return memberships
