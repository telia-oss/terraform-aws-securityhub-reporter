## Securityhub reporter lambda


This module creates a lambda that will read status of selected controls in Security Hub's `AWS Foundational Security Best Practices v1.0.0` and reports the results to the selected Slack channel (optional) and custom Cloudwatch metric.


### Localy set security control ids

Selected controls are passed to Lambda function through terraform variable
``` terraform
variable "security_controls" {
    description = "Comma separated list of controls that should be checked."
    type        = string
}
```
This variable is mandatory and value from it is used as a fallback when call to remote API which provides list of security controls for checking fails.

### Externally set security control ids

This lambda can be set so that it obtains list of security controls from external API. It uses three parameters from  aws parameter store 
to obtain information about the API. These parameter names set by these four variables:
```terraform 
variable "ps_root_path" {
  type = string
  default = "/SecurityReporter/"
}

variable "ps_key_security_controls_api_resource_path" {
  type = string
  default = "securityControlsApiResourcePath"

}

variable "ps_key_security_controls_api_key" {
  type = string
  default = "securityControlsApiKey"
}

variable "ps_key_security_controls_api_host" {
  type = string
  default = "securityControlsApiHost"
}
```
1. **ps_root_path:** Path under which the parameters are stored. Lambda loads all params under this path
2. **ps_key_security_controls_api_host:** Name of the SSM parameter where a host to REST API returning controls ID is stored. The Parameter is created under `ps_root_path`.
3. **ps_key_security_controls_api_key:** Name of the SSM parameter where api key to REST API returning controls ID is stored. For now x-api-key header is used for authentication. The Parameter is created under `ps_root_path`.
4. **ps_key_security_controls_api_host:** Name of the SSM parameter where resource path to REST API returning controls ID is stored.The Parameter is created under `ps_root_path`.

All these ssm parameters are created when terraform is applied with default value and users then manually change them to correct values.
If any of the params is not created or holds default value then the lambda function uses locally set security controls.
The API must return json in following structure:

```json
{
  "data":  {
    "ControlIds": []
  }
}
``` 
