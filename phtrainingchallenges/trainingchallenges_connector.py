# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from trainingchallenges_consts import *
import requests
import json


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TrainingChallengesConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TrainingChallengesConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _generate_final_challenge(self):
        container_data = {}
        container_data['name'] = "Challenge Data Set 3"
        container_data['description'] = "Challenge Data"
        
        return_value, response, container_id = self.save_container(container_data)

        artifact_ips = ['8.8.8.8', '10.10.10.10', '192.168.50.27']
        artifact_names = ['sample data set 1', 'sample data set 2', 'sample data set 3']

        for i,j in zip(artifact_ips, artifact_names):
            artifact = {}
            artifact['name'] = j
            artifact['cef'] = {'sourceAddress':i}
            artifact['container_id'] = container_id
            return_value, status_string, artifact_id = self.save_artifact(artifact)

    def _handle_test_connectivity(self, param):
        return self.set_status_save_progress(phantom.APP_ERROR, "not implemented")


    def _handle_on_poll(self, param):
        config = self.get_config()
        user_email = config.get("email")
        
        container_names = ["Challenge Data Set 1-A",
                           "Challenge Data Set 1-B",
                           "Challenge Data Set 1-C",
                           "Challenge Data Set 1-D",
                           "Challenge Data Set 1-E",
                           "Challenge Data Set 2-A",
                           "Challenge Data Set 2-B"]
        
        artifact_data = [
            {
                "name":"sample data set 1-A",
                "cef": {
                    "fileHash":"0ca4f93a848cf01348336a8c6ff22daf",
                    "requestURL":"http://www.posterminalworld.la"
                    }
                },
            {
                "name":"sample data set 1-B",
                "cef": {
                    "fileHash":"c3884e803e1d5d6cc94d559e543839ab",
                    "requestURL":"http://www.phantom.us"
                    }
                },
            {
                "name":"sample data set 1-C",
                "cef": {
                    "fileHash":"7fb22b5a6cbe5c639ece19a840659d4b",
                    "requestURL": "http://propanel.ml"
                    }
                },
            {
                "name": "sample data set 1-D",
                "cef": {
                    "fileHash":"e98733af653bc6f8743052a6ac264587",
                    "requestURL": "http://propanel.ml"
                    }
                },
            {
                "name": "sample data set 1-E",
                "cef": {
                    "fileHash": "ffcc895f7aae433305174767e8127633",
                    "requestURL": "http://www.posterminalworld.la"
                    }
                },
            {
                "name":"sample data set 3",
                "cef": {
                    "fromEmail":user_email,
                    "requestURL":"http://www.posterminalworld.la"
                    },
                "cef_types": {
                    "fromEmail": ["email"]
                    }
                },
            {
                "name":"sample data set 4",
                "cef": {
                    "fromEmail":user_email,
                    "requestURL":"http://www.phantom.us"
                    },
                "cef_types": {
                    "fromEmail": ["email"]
                    }
                }
            ]
        
        # generate the initial containers for the first four challenges
        for i,j in zip(container_names, artifact_data):
            container_data = {}
            container_data['name'] = i
            container_data['description'] = "Challenge Data"
            
            return_value, response, container_id = self.save_container(container_data)
            artifact = {}
            artifact.update(j)
            artifact["container_id"] = str(container_id)
            
            return_value, status_string, artifact_id = self.save_artifact(artifact)
        
        # generate the final challenge
        self._generate_final_challenge()

        if phantom.is_fail(return_value):
            return self.set_status_save_progress(phantom.APP_ERROR, "error")
        else:
            return self.set_status_save_progress(phantom.APP_SUCCESS, "success")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TrainingChallengesConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
