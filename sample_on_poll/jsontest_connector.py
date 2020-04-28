
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from jsontest_consts import *
import requests
import json

class JsonTestConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(JsonTestConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None


    def _handle_test_connectivity(self, param):

        self.save_progress("Attempting to connect to json test site")
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, "http://date.jsontest.com/")

        sample_site_data = requests.get("http://date.jsontest.com/")

        # not really doing much error checking

        if sample_site_data.status_code == 200:
            return self.set_status_save_progress(phantom.APP_SUCCESS,"success")
        else:
            return self.set_status_save_progress(phantom.APP_ERROR, "error")


    def _handle_on_poll(self, param):

        # print out the params to show what is available
        self.save_progress("Params: ")
        self.save_progress(str(param))

        # get our sample json data
        sample_json_data_results = requests.get("http://ip.jsontest.com/").json()
        
        # create the container for the json data
        container = {}
        container["name"] = "Test Ingest Container"
        container["description"] = "Test data from json test site"

        return_value, response, container_id = self.save_container(container)
        
        # add our artifacts to the newly created container
        artifact = {
            'name':'sample json data', 
            'description':'current ip address', 
            'cef':{
                'sourceAddress':sample_json_data_results["ip"]}, 
            'container_id':container_id}
        
        return_value, status_string, artifact_id = self.save_artifact(artifact)
        
        # return success or error based on whether or not we were able to add an artifact to our container
        if phantom.is_fail(return_value):
            return self.set_status_save_progress(phantom.APP_ERROR,"error")
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

        """
        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

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

        connector = JsonTestConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
