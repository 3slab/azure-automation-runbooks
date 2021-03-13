# Import python3 package in automation account

An official runbook [import_py3package_from_pypi.py](https://github.com/azureautomation/runbooks/blob/master/Utility/Python/import_py3package_from_pypi.py) exists but with issues :

* [#79](https://github.com/azureautomation/runbooks/issues/79)
* [#78](https://github.com/azureautomation/runbooks/pull/78)
* [#77](https://github.com/azureautomation/runbooks/pull/77)

This version adresses some of these issues.

## Usage

1. Create a runbook with the script

2. Run it with the following parameters

    * subscription_id (-s) - Subscription id of the Automation account
    * resource_group (-g) - Resource group name of the Automation account
    * automation_account (-a) - Automation account name
    * module_name (-m) - Name of module to import from pypi.org
    
3. Check you automation account python packages page in azure portal to view the imported packages.

*Note : you can provide multiple module names with a coma separated list*

*Note 2 : you can force a version in the module name. Example : azure-mgmt-containerservice==15.0.0,azure-mgmt-compute==19.0.0*