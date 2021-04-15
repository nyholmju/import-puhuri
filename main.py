#!/usr/bin/env python3

"""
Pulls in data from Puhuri Core REST APIs and generates CSV files.
"""

__author__ = "Juha Nyholm"
__version__ = "0.1.0"
__license__ = "MIT"

import argparse
import os.path
import fcntl
import requests
import json
import time
from logzero import logger, logfile
from datetime import datetime, date

class PuhuriUser:
    """ Model for PuhuriUser """
    def __init__(self, uuid, importDate, puhuriUserUniqueId=None, givenName=None, surname=None, mail=None, telephoneNumber=None, schacCountryOfCitizenship=None, schacHomeOrganization=None, userType=None, isActive=None):
        self.uuid = uuid # Puhuri Core UUID
        self.importDate = importDate # Set to current date in ctime format.
        self.puhuriUserUniqueId = puhuriUserUniqueId # Puhuri AAI CUID
        self.givenName = givenName
        self.surname = surname
        self.mail = mail
        self.telephoneNumber = telephoneNumber # TODO
        self.schacCountryOfCitizenship = schacCountryOfCitizenship # TODO
        self.schacHomeOrganization = schacHomeOrganization # TODO
        self.userType = userType # TODO
        self.isActive = isActive
        self.sshPublicKeys = []
        self.eduPersonAssurances = [] # TODO

    def add_sshPublicKey(self, sshPublicKey):
        self.sshPublicKeys.append(sshPublicKey)

    def add_eduPersonAssurance(self, eduPersonAssurance):
        self.eduPersonAssurances.append(eduPersonAssurance)

class PuhuriProject:
    """ Model for PuhuriProject """
    def __init__(self, uuid, importDate, title=None, description=None, homeOrganization=None, projectType=None, startTimestamp=None, endTimestamp=None, status=None, allocatedCPUHours=0, allocatedGPUHours=0, allocatedStorageHours=0, principalInvestigatorUniqueId=None):
        self.uuid = uuid # Puhuri Core UUID
        self.importDate = importDate # Set to current date in ctime format.
        self.title = title
        self.description = description
        self.projectType = projectType
        self.homeOrganization = homeOrganization # TODO
        self.startTimestamp = startTimestamp # TODO
        self.endTimestamp = endTimestamp # TODO
        self.status = status
        self.allocatedCPUHours = allocatedCPUHours # TODO
        self.allocatedGPUHours = allocatedGPUHours # TODO
        self.allocatedStorageHours = allocatedStorageHours # TODO
        self.principalInvestigatorUniqueId = principalInvestigatorUniqueId
        self.proxyPrincipalInvestigatorUniqueIds = []
        self.memberUniqueIds = []

    def add_proxyPrincipalInvestigatorUniqueId(self, proxyPrincipalInvestigatorUniqueId):
        self.proxyPrincipalInvestigatorUniqueIds.append(proxyPrincipalInvestigatorUniqueId)

    def add_memberUniqueId(self, memberUniqueId):
        self.memberUniqueIds.append(memberUniqueId)

class WaldurTokenAuth(requests.auth.AuthBase):
    """ Waldur REST API uses token based authorization """
    def __init__(self, api_token):
        self.api_token = api_token
    def __call__(self, r):
        r.headers['Authorization'] = 'token ' + self.api_token
        return r

def refresh_api_token(args):
    """ Checks the validity of persisted API token and fetches a new API token from authentication endpoint if needed """

    # Initialize api_token with None type.
    api_token = None

    # Attempt to read the persisted API token from the file system.
    if os.path.isfile(args.token_file):
        try:
            fd = open(args.token_file, 'r')
            api_token = fd.read()
            fd.close()
        except (IOError, FileNotFoundError, IsADirectoryError, PermissionError) as ex:
            logger.error("{}: {}".format(type(ex).__name__, ex))
            raise

    # Persisted API token was read from file system.
    if (api_token):
        # Check validity of persisted API token by calling /api/ endpoint in Waldur.
        api_endpoint = args.base_url + '/api/'
        try:
            r = requests.get(api_endpoint, auth=WaldurTokenAuth(api_token))
        except (requests.exceptions.RequestException) as ex:
            logger.error("{}: {}".format(type(ex).__name__, ex))
            raise

        # Persisted API token is still valid when /api/ endpoint returns http status code 200.
        if r.status_code == 200:
            logger.debug("Persisted API token is still vaild, reusing token.")
            return api_token

    # Persisted API token is not valid or missing, fetch a new API token by calling password authentication endpoint.
    logger.debug("No vaild API token is available, fetching a new API token by calling autentication endpoint with supplied credentials.")
    auth_endpoint = args.base_url + '/api-auth/password/'
    try:
        r = requests.post(auth_endpoint, data = {'username':args.user, 'password':args.password })
        r.raise_for_status()
        json_data = r.json()
    except (requests.exceptions.RequestException, json.decoder.JSONDecodeError) as ex:
        logger.error("{}: {}".format(type(ex).__name__, ex))
        raise

    if 'token' not in json_data:
        logger.error("Error: API token data is missing in json payload returned by /api-auth/password/ endpoint.")
        raise ValueError('Response does not contain API token')

    api_token = json_data["token"]

    # Persist the new API token in file system.
    try:
        fd = open(args.token_file, 'w+')
        fd.write(api_token)
        fd.close()
    except (IOError, IsADirectoryError, PermissionError) as ex:
        logger.error("{}: {}".format(type(ex).__name__, ex))
        raise

    return api_token

def get_data_from_api_endpoint(api_token, api_endpoint):
    """ Returns all available data in JSON format from given API endpoint
        Note: API endpoint may return a list (array of json objects) or a dict (json object)
        Relevant parts copied from https://github.com/opennode/ansible-waldur-module/blob/6679b6b8f9ca21099eb3a6cb97e846d3e8dd1249/waldur_client.py
    """
    try:
        r = requests.get(api_endpoint, auth=WaldurTokenAuth(api_token))
        r.raise_for_status()
        json_data = r.json()
    except (requests.exceptions.RequestException, json.decoder.JSONDecodeError) as ex:
        logger.error("{}: {}".format(type(ex).__name__, ex))
        raise
    if 'Link' not in r.headers: # Results are paged if 'Link' is present.
        return json_data
    while 'next' in r.headers['Link']:
        if 'prev' in r.headers['Link']:
            next_url = r.headers['Link'].split(', ')[2].split('; ')[0][1:-1]
        else:  # First page case.
            next_url = r.headers['Link'].split(', ')[1].split('; ')[0][1:-1]
        try:
            r = requests.get(next_url, auth=WaldurTokenAuth(api_token))
            r.raise_for_status()
            json_data += r.json()
        except (requests.exceptions.RequestException, json.decoder.JSONDecodeError) as ex:
            logger.error("{}: {}".format(type(ex).__name__, ex))
            raise
    return json_data

def get_users_from_puhuri_api(args, api_token):
    """ Fetches user data from given API endpoints """
    logger.info("get_users_from_puhuri_api function started running.")
    puhuriUsers = []
    api_endpoint = args.base_url + '/api/users/?registration_method=eduteams'
    users_json = get_data_from_api_endpoint(api_token, api_endpoint)
    if isinstance(users_json, list):
        importDate = int(datetime.combine(date.today(), datetime.min.time()).timestamp())
        for user_json in users_json:
            puhuriUser = PuhuriUser(user_json['uuid'], importDate)
            if 'username' in user_json:
                puhuriUser.puhuriUserUniqueId = user_json['username']
## TODO: We need better data for givenName and surname, since they are tricky to parse correctly from full_name
            if 'full_name' in user_json:
                puhuriUser.givenName = user_json['full_name'].split(' ', 1)[0]
                puhuriUser.surname = user_json['full_name'].split(' ', 1)[1]
            if 'email' in user_json:
                puhuriUser.mail = user_json['email']
            if 'phone_number' in user_json:
                puhuriUser.telephoneNumber = user_json['phone_number']
## TODO:
# Add:
#            if '' in user_json:
#                puhuriUser.schacCountryOfCitizenship =
#            if '' in user_json:
#                puhuriUser.schacHomeOrganization = 
#            if '' in user_json:
#                puhuriUser.userType = 
            if 'is_active' in user_json:
                puhuriUser.isActive = user_json['is_active'] 
            api_endpoint = args.base_url + '/api/keys/?user_uuid=' + puhuriUser.uuid
            ssh_pub_keys_json = get_data_from_api_endpoint(api_token, api_endpoint)
            if isinstance(ssh_pub_keys_json, list):
                for ssh_pub_key_json in ssh_pub_keys_json:
                    ssh_pub_key = ssh_pub_key_json['public_key']
                    # Sanitize the ssh public key comment field by replacing '|' characters with '_' characters.
                    # We do this because we use the '|' character as a delimiter when exporting multivalued ssh public key data to csv.
                    if len(ssh_pub_key.split()) >= 3:
                        # The ssh public key contains the optional comment field, let's see if we need to sanitize it.
                        tmpList = ssh_pub_key.split()
                        if '|' in tmpList[-1]:
## TODO:
# Revisit this:
                            # The '|' character was found in the comment field, let's sanitize the input.
                            sanitized_comment_field = tmpList[-1].replace('|', '_')
                            tmpList[-1] = sanitized_comment_field
                            ssh_pub_key = ' '.join(tmpList)
                    puhuriUser.add_sshPublicKey(ssh_pub_key)
            else:
                logger.error("Error: Expecting ssh_pub_keys_json to be in list format.")
## TODO:
# Add:
#            if '' in user_json:
#                puhuriUser.add_eduPersonAssurance(eduPersonAssurance) 
            puhuriUsers.append(puhuriUser)
    else:
        logger.error("Error: Expecting users_json to be in list format.")

    logger.info("get_users_from_puhuri_api function finished running. Found {} users.".format(len(puhuriUsers)))
    return puhuriUsers

def get_projects_from_puhuri_api(args, api_token):
    """ Fetches project data from given API endpoints """
    logger.info("get_projects_from_puhuri_api function started running.")
    puhuriProjects = []
    api_endpoint = args.base_url + '/api/projects'
    projects_json = get_data_from_api_endpoint(api_token, api_endpoint)
    if isinstance(projects_json, list):
        importDate = int(datetime.combine(date.today(), datetime.min.time()).timestamp())
        for project_json in projects_json:
            puhuriProject = PuhuriProject(project_json['uuid'], importDate)
            if 'name' in project_json:
                puhuriProject.title = project_json['name']
            if 'description' in project_json:
## TODO:
# Add:
#            if '' in project_json:
#                puhuriProject.projectType =
                puhuriProject.description = project_json['description']
            if 'homeOrganization' in project_json:
                puhuriProject.homeOrganization = project_json['homeOrganization']
            if 'startTimestamp' in project_json:
                puhuriProject.startTimestamp = project_json['startTimestamp']
            if 'endTimestamp' in project_json:
                puhuriProject.endTimestamp = project_json['endTimestamp']
            if 'status' in project_json:
                puhuriProject.status = project_json['status']
## TODO:
# Add:
#            if '' in project_json:
#                puhuriProject.allocatedCPUHours =
## TODO:
# Add:
#            if '' in project_json:
#                puhuriProject.allocatedGPUHours =
## TODO:
# Add:
#            if '' in project_json:
#                puhuriProject.allocatedStorageHours =
            # Project principal investigators have role 'manager' in Waldur.
            api_endpoint = args.base_url + '/api/project-permissions/?&role=manager&project=' + puhuriProject.uuid
            project_principalInvestigators_json = get_data_from_api_endpoint(api_token, api_endpoint)
            if isinstance(project_principalInvestigators_json, list):
                for project_principalInvestigator_json in project_principalInvestigators_json:
                    if 'user_username' in project_principalInvestigator_json:
                        # Note: puhuriProject.principalInvestigatorUniqueId is single-valued. If there are multiple PI's
                        #       listed in Waldur, puhuriProject.principalInvestigatorUniqueId will be set to the last 
                        #       'user_username' entry that is returned by the 'project-permissions/?&role=manager' API call.
                        puhuriProject.principalInvestigatorUniqueId = project_principalInvestigator_json['user_username']
                        # Waldur does not allow users to have multiple roles within a project.
                        # We need to explicitly append the user with project PI role to to project member list,
                        # since the user with project PI role does not have a member role for the project in Waldur.
                        puhuriProject.add_memberUniqueId(project_principalInvestigator_json['user_username'])
            else:
                logger.error("Error: Expecting project_principalInvestigators_json to be in list format.")
            # Project proxy principal investigators have role 'admin' in Waldur.
            api_endpoint = args.base_url + '/api/project-permissions/?&role=admin&project=' + puhuriProject.uuid
            project_proxyPrincipalInvestigators_json = get_data_from_api_endpoint(api_token, api_endpoint)
            if isinstance(project_proxyPrincipalInvestigators_json, list):
                for project_proxyPrincipalInvestigator_json in project_proxyPrincipalInvestigators_json:
                    if 'user_username' in project_proxyPrincipalInvestigator_json:
                        puhuriProject.add_proxyPrincipalInvestigatorUniqueId(project_proxyPrincipalInvestigator_json['user_username'])
                        # Waldur does not allow users to have multiple roles within a project.
                        # We need to explicitly append the user with project proxy PI role to to project member list,
                        # since the user with project proxy PI role does not have a member role for the project in Waldur.
                        puhuriProject.add_memberUniqueId(project_proxyPrincipalInvestigator_json['user_username'])
            else:
                logger.error("Error: Expecting project_proxyPrincipalInvestigators_json to be in list format.")
            # Project members have role 'member' in Waldur.
            api_endpoint = args.base_url + '/api/project-permissions/?role=member&project=' + puhuriProject.uuid
            project_members_json = get_data_from_api_endpoint(api_token, api_endpoint)
            if isinstance(project_members_json, list):
                for project_member_json in project_members_json:
                    if 'user_username' in project_member_json:
                        puhuriProject.add_memberUniqueId(project_member_json['user_username'])
            else:
                logger.error("Error: Expecting project_members_json to be in list format.")
            puhuriProjects.append(puhuriProject)
    else:
        logger.error("Error: Expecting projects_json to be in list format.")

    logger.info("get_projects_from_puhuri_api function finished running. Found {} projects.".format(len(puhuriProjects)))
    return puhuriProjects

def write_users_to_csv_file(args, users):
    """ Generates a CSV file from supplied list of users """
    logger.info("write_users_to_csv_file function started running.")
    import csv
    with open(args.output_directory + 'users/in/users-' + str(int(time.time())) + '.csv', 'w', encoding='utf8', newline='') as csvfile:
        user_csv_writer = csv.writer(csvfile, delimiter='|', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        for user in users:
            user_csv_writer.writerow([user.uuid, user.importDate, user.puhuriUserUniqueId, user.givenName, user.surname, user.mail, user.telephoneNumber, user.schacCountryOfCitizenship, user.schacHomeOrganization, user.userType, user.isActive, '|'.join(user.sshPublicKeys), '|'.join(user.eduPersonAssurances)])
    logger.info("write_users_to_csv_file function finished running.")

def write_projects_to_csv_file(args, projects):
    """ Generates a CSV file from supplied list of projects """
    logger.info("write_projects_to_csv_file function started running.")
    import csv
    with open(args.output_directory + 'projects/in/projects-' + str(int(time.time())) + '.csv', 'w', encoding='utf8', newline='') as csvfile:
        project_csv_writer = csv.writer(csvfile, delimiter='|', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        for project in projects:
            project_csv_writer.writerow([project.uuid, project.importDate, project.title, project.description, project.projectType, project.homeOrganization, project.startTimestamp, project.endTimestamp, project.status, project.allocatedCPUHours, project.allocatedGPUHours, project.allocatedStorageHours, project.principalInvestigatorUniqueId, '|'.join(project.proxyPrincipalInvestigatorUniqueIds), '|'.join(project.memberUniqueIds)])
    logger.info("write_projects_to_csv_file function finished running.")

def acquire_lockfile(file_path):
    """ Generates lock file to prevent running multiple instances of the script at the same time """
    try:
        fd = open(file_path, 'w')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except (IOError, PermissionError):
        return None

def main(args):
    """ Main entry point of the app """
    api_token = refresh_api_token(args)
    users = get_users_from_puhuri_api(args, api_token)
    projects = get_projects_from_puhuri_api(args, api_token)
    write_users_to_csv_file(args, users)
    write_projects_to_csv_file(args, projects)

if __name__ == "__main__":
    """ This is executed when run from the command line """

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-b",
        "--base_url",
        default="https://puhuri-core.domain.tld",
        help="The base url that is used in API call.")

    parser.add_argument(
        "-o",
        "--output_directory",
        default="/home/import/csv/",
        help="The output directory where csv files will be stored.")

    parser.add_argument(
        "-u",
        "--user",
        help="Username used to request API token.",
        required=True)

    parser.add_argument(
        "-p",
        "--password",
        help="Password used to request API token.",
        required=True)

    parser.add_argument(
        "-t",
        "--token_file",
        default="/home/import/secrets/api_token",
        help="The output file where the API token will be stored.")

    parser.add_argument(
        "-l",
        "--log_directory",
        default="/home/import/log/",
        help="The directory where log files will be stored.")

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s (version {version})".format(version=__version__))

    args = parser.parse_args()

    logfile(args.log_directory + '/import-puhuri.log', disableStderrLogger=True)

    logger.info("Puhuri import script started running.")

    fd = acquire_lockfile("/tmp/import-puhuri.lock")
    if fd:
        main(args)
    else:
        logger.error("Error: Didn't get lock file - bailing out.")

    logger.info("Puhuri import script finished running.")
