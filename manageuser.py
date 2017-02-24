import requests
import json
import re

from requests.auth import HTTPBasicAuth


def check_password(password):

    """
    :param password: input password
    :return result: contains a list of errors and password status
    """

    length_error = len(password) < 8
    if length_error:
        length_error = 'password should be longer than 8 characters'

    # searching for digits
    digit_error = re.search(r"\d", password) is None
    if digit_error:
        digit_error = 'password must contain digits'

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None
    if uppercase_error:
        uppercase_error = 'password must contain uppercase characters'

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None
    if lowercase_error:
        lowercase_error = 'password must contain lowercase characters'

    # searching for symbols
    symbol_error = re.search(r"\W", password) is None
    if symbol_error:
        symbol_error = 'password must contain special characters'

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    result = {
        'password_ok': password_ok,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error
    }

    return result

def get_auth_token(cso_ip, login, password):

    """
    :param cso_ip: Keystone endpoint on default port(5000)
    :param login: CSO superuser admin username
    :param password: CSO superuser admin password
    :return: authentication token

    """

    print 'fetching auth token'

    auth_token = "null"
    url = "http://" + cso_ip + ":5000/v3/auth/tokens"
    auth = HTTPBasicAuth(login, password)  # might need to use b64encode here
    headers = {
                'authorization': auth,
                'content-type': "application/json"
            }
    try:
        r = requests.post(url, headers)
        auth_token = r.headers['X-Subject-Token']
        print 'done'
    except requests.exceptions.HTTPError:
        error_msg = 'error getting auth token'
        print error_msg
    finally:
        return auth_token


def assign_user_roles(uid, cso_ip, token):

    """

    :param uid: uuid of the user that is added
    :param cso_ip: Keystone endpoint on default port(5000)
    :param token: auth token from keystone
    :return: none

    Used to assign admin role and default project uuid to the user.

    Workflow:

    1. Fetch admin user role and default project ID
    2. assign the admin role and the default project to the added user

    """
    print "Assigning user privileges..."

    # setting defaults
    proj_default_uuid = 'null'
    admin_role_uuid = 'null'

    # Fetching admin role uuid and default project uuid

    url_project = "http://" + cso_ip + ":5000/v3/projects"
    url_role = "http://" + cso_ip + ":5000/v3/roles"

    headers = {
        'x-auth-token:': token,
        'content-type': "application/json"
    }

    # get default project uuid
    r1 = requests.get(url_project, headers=headers)
    projects = r1.json()
    for project in projects['projects']:
        if project['description'] == "Admin Tenant":
            proj_default_uuid = project['id']

    # get admin role uuid
    r2 = requests.get(url_role, headers=headers)
    roles = r2.json()
    for role in roles['roles']:
        if role['name'] == 'admin':
            admin_role_uuid = role['id']

    # Assigning user privileges

    url = "http://" + cso_ip + ":5000/v3/projects/" + proj_default_uuid + "/users/" + uid + "/roles/" + admin_role_uuid
    payload = "null"
    try:
        res = requests.put(url, data=payload)
        if res.status_code == "200":
            print "Admin user added successfully!"
    except requests.exceptions.HTTPError:
        error_msg = "Error in assigning privileges to user"
        print error_msg
        print 'User add unsuccessful'


def useradd():

    """
    :return: none
    Function to add user to keystone.
    Workflow:
    1. Fetch auth token
    2. Add user to keystone

    """

    cso_ip = raw_input('Keystone IP: ')
    login = raw_input('Admin username: ')
    password = raw_input('Admin password: ')
    userid = raw_input('New user to add: ')
    userpass = raw_input('Password for new user: ')

    result = check_password(userpass)
    if result['password_ok']:
        user_pass = userpass
    else:
        print 'Password does not match IT security standards!'
        if result['length_error']:
            print str(result['length_error'])
        if result['digit_error']:
            print str(result['digit_error'])
        if result['uppercase_error']:
            print str(result['uppercase_error'])
        if result['lowercase_error']:
            print str(result['lowercase_error'])
        if result['symbol_error']:
            print str(result['symbol_error'])
        return

    print 'Attempting to add user to keystone...'

    token = get_auth_token(cso_ip, login, password)

    # default
    true = bool(1)
    url = "http://" + cso_ip + ":5000/v3/users"
    headers = {
        'x-auth-token': token,
        'content-type': "application/json"
    }
    payload = {
        "user": {
            "domain-id": "default",
            "enabled": true,
            "name": userid,
            "password": user_pass
        }
    }
    res = requests.post(url, headers=headers, data=json.dumps(payload))
    r = res.json()
    if res.status_code == "200":
        uid = r['user']['id']
        print 'User added to keystone.'
        # assigning user with admin role and default project
        assign_user_roles(uid, cso_ip, token)
    else:
        print 'unable to add user'


def deluser(cso_ip, uid, token):

    """

    :param cso_ip: Keystone IP address
    :param uid: UUID of user on Keystone
    :param token: Auth token from Keystone
    :return null

    This is used to separate UUID fetch from actual delete.
    """

    url_b = "http://" + cso_ip + ":5000/v3/users/" + uid
    headers = {
        'x-auth-token': token,
        'content-type': "application/json"
    }
    try:
        requests.delete(url_b, headers=headers)
        print "User delete successful"
    except requests.exceptions.HTTPError as e:
        print 'encountered an error when deleting user. User delete not successful'
        print 'info: UID: ' + uid + '. Error: ' + str(e)


def usermod(cso_ip, uid, token, user_pass):
    """

    :return:
    """
    url_b = "http://" + cso_ip + ":5000/v3/users/" + uid
    headers = {
        'x-auth-token': token,
        'content-type': "application/json"
    }
    payload = {
        "user": {
            "password": user_pass
        }
    }
    try:
        requests.patch(url_b, headers=headers, data=json.dumps(payload))
        print "User password reset successful"
    except requests.exceptions.HTTPError as e:
        print 'encountered an error when resetting user password. Operation not successful'
        print 'info: UID: ' + uid + '. Error: ' + str(e)


def userdelete():

    """
    Takes no params
    :return: Null

    workflow:
       1 fetch auth token
       2 fetch uuid for the user to be deleted
       3 delete user by calling the deluser() function
    """

    cso_ip = raw_input('Keystone IP: ')
    login = raw_input('Admin username: ')
    password = raw_input('Admin password: ')
    userid = raw_input('User to delete: ')

    print 'Attempting to delete user ' + userid + ' ...'
    token = get_auth_token(cso_ip, login, password)

    # setting headers for future API calls:
    headers = {
        'x-auth-token': token,
        'content-type': "application/json"
    }

    print 'fetching uuid for user...'
    url_a = "http://" + cso_ip + ":5000/v3/users"
    try:
        res = requests.get(url_a, headers=headers)
        response = res.json()

        for user in response['users']:
            if user['name'] == userid:
                uid = user['id']
                deluser(cso_ip, uid, token)
            else:
                # user not found
                print 'user not found on keystone'

    except requests.exceptions.HTTPError as e:
        print "error while trying to retrieve user list. Error: " + str(e)
        print "User delete not successful"


def user_reset():

    """
    Takes no params
    :return: Null

    workflow:
       1 fetch auth token
       2 fetch uuid for the user whose password needs to be reset
       3 Modify user by calling the usermod() function

    """

    cso_ip = raw_input('Keystone IP: ')
    login = raw_input('Admin username: ')
    password = raw_input('Admin password: ')
    userid = raw_input('User to modify: ')
    userpass = raw_input('New password for user: ')

    result = check_password(userpass)
    if result['password_ok']:
        user_pass = userpass
    else:
        print 'Password does not match IT security standards!'
        if result['length_error']:
            print str(result['length_error'])
        if result['digit_error']:
            print str(result['digit_error'])
        if result['uppercase_error']:
            print str(result['uppercase_error'])
        if result['lowercase_error']:
            print str(result['lowercase_error'])
        if result['symbol_error']:
            print str(result['symbol_error'])
        return

    print 'Attempting to add user to keystone...'
    print 'Attempting to reset password for user ' + userid + ' ...'
    token = get_auth_token(cso_ip, login, password)

    # setting headers for future API calls:
    headers = {
        'x-auth-token': token,
        'content-type': "application/json"
    }

    print 'fetching uuid for user...'
    url_a = "http://" + cso_ip + ":5000/v3/users"
    try:
        res = requests.get(url_a, headers=headers)
        response = res.json()

        for user in response['users']:
            if user['name'] == userid:
                uid = user['id']
                usermod(cso_ip, uid, token, user_pass)
            else:
                # user not found
                print 'user not found on keystone'

    except requests.exceptions.HTTPError as e:
        print "error while trying to retrieve user list. Error: " + str(e)
        print "Password reset not successful"


###############################################################################
#                                MAIN MENU                                    #
###############################################################################

print '----- MAIN MENU -----'
print '1 Add user'
print '2 Reset user password'
print '3 Delete user'
print ' '
option = raw_input('Select an option(1-3): ')

if option == '1':
    useradd()
elif option == '2':
    user_reset()
elif option == '3':
    userdelete()
else:
    print "Invalid option."

################################################################################
