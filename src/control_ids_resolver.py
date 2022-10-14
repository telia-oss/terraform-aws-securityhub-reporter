import boto3, logging, http.client, json, botocore


class ControlIdsResolver:
    DEFAULT_PARAMS_VALUE: str = "NOT_SET"

    def __init__(self, security_controls, ssm_param_root_path, parameter_name_api_host, parameter_name_api_key,
                 parameter_name_api_resource_path):
        self.local_security_control_id = security_controls.replace(' ', '').split(',')
        self._ssm_param_root_path = ssm_param_root_path
        self._parameter_name_api_host = self._ssm_param_root_path + parameter_name_api_host
        self._parameter_name_api_key = self._ssm_param_root_path + parameter_name_api_key
        self._parameter_name_api_resource_path = self._ssm_param_root_path + parameter_name_api_resource_path
        self._ssm = boto3.client('ssm')
        self._get_param_store_configs()
        self._ignore_api = self._is_api_config_valid()
        self._centralized_security_control_ids = self._get_centralized_security_controls()

    def _get_param_store_configs(self) -> dict:
        try:
            response = self._ssm.get_parameters_by_path(
                Path=self._ssm_param_root_path,
                WithDecryption=True
            )
            parameters = response['Parameters']
            self._control_ids_api_details = {parameter['Name']: parameter['Value'] for parameter in parameters if
                                             parameter['Name'] in [self._parameter_name_api_host,
                                                                   self._parameter_name_api_key,
                                                                   self._parameter_name_api_resource_path]}
        except botocore.exceptions.ClientError as e:
            logging.exception(e.response)
            self._control_ids_api_details = dict()

    def _is_api_config_valid(self):
        if len(self._control_ids_api_details) != 3 or ControlIdsResolver.DEFAULT_PARAMS_VALUE in self._control_ids_api_details.values():
            logging.warning(f"setup for control-ids api is considered not valid. {self._control_ids_api_details}")
            return False
        return True

    def _get_centralized_security_controls(self):
        logging.warning(f"api details for obtaining control ids {self._control_ids_api_details}")
        if not self._ignore_api:
            logging.warning(f"skipping obtaining data from control-id api.")
            return []
        try:
            headers = {
                'x-api-key': self._control_ids_api_details[self._parameter_name_api_key],
                'Content_Type': 'application/json'
            }
            connection = http.client.HTTPSConnection(self._control_ids_api_details[self._parameter_name_api_host])
            connection.request("GET", self._control_ids_api_details[self._parameter_name_api_resource_path], "",
                               headers)
            response = connection.getresponse()
            r_body = json.loads(response.read().decode())
            connection.close()
            return r_body['data']['ControlIds']
        except Exception as e:
            logging.exception(f"This error happened when requesting security controls from api: {e.__repr__()}")
            return []

    def get_security_controls(self):
        if len(self._centralized_security_control_ids) > 0:
            logging.info(
                f"Control ids from api will be used. Here are the values: {self._centralized_security_control_ids}")
            return self._centralized_security_control_ids
        else:
            logging.warning(
                f"Locally set control ids will be used. Here are the values: {self.local_security_control_id}")
            return self.local_security_control_id
