# AKS Start/Stop

This is a python3 script to be used in an Azure Automation Runbook in order to automatize AKS start/stop operation.

## Usage

    python startstop.py <action> <clusters> [--use-vmss] [--dry-run] [--disable-check-state] [--disable-power-state]
    [--auth-mode=<auth_mode>]

Script needs 2 mandatory positional arguments :

* `action` : start/stop
* `clusters` : coma separated list of AKS cluster names

Other arguments are optionals :

* `--use-vmss` : if the cluster uses vmss, then instead of calling start/stop on the cluster itself, it
    starts/deallocates vmss instances.
* `--use-availability-set` : if the cluster uses availabilityset, then instead of calling start/stop on the cluster
    itself, it starts/deallocates each vm individually
* `--dry-run` : run script in dry run mode
* `--disable-check-state` : disable checking if the cluster is in Succeeded state before doing anything
* `--disable-power-state` : disable checking if the cluster is in running/stopped state before doing anything
* `--auth-mode=<auth_mode>` : set auth mode (see README in github repo)

## Automation account installation

1. Load needed python packages. At the time of writing, the python3 SDK available per default in the runbook is too old
for the start/stop feature. You need to import newest packages. 
   
    Load [import-py3package](../import-py3package) runbook and start it with the following parameters :

```
-s <your subscription>
-g <your automation account resource group>
-a <your automation account name>
-m azure-mgmt-containerservice==15.0.0,azure-mgmt-compute==19.0.0,azure-mgmt-resource==16.0.0,azure-identity==1.5.0
```

*Note : order of module is important. Identity needs to be last because of cryptography package*

2. However there are issues with local shared libraries and conflicts between versions. Right now, I did not manage 
   to make it works with the run as credentials. The only way I found was to create crypted automation variables based
   on a service principal to use the [ClientSecretCredential](https://azuresdkdocs.blob.core.windows.net/$web/python/azure-identity/1.4.0/azure.identity.html#azure.identity.ClientSecretCredential)
   
    You will need to provide 4 variables with this name :

     * `External_AksStartStop_TenantId`
     * `External_AksStartStop_ClientId`
     * `External_AksStartStop_ClientSecret`
     * `Internal_AzureSubscriptionId`


3. Run the start/stop script with the parameter `--auth-mode=automationvariables`

*Note : implicitly it means that run as azure credentials is not working for this library and python version.*

## Monitoring

You can create alert in log analytics based on these queries

if you use standard start/stop mode :

```
AzureActivity 
    | where OperationName in ("Microsoft.ContainerService/managedClusters/start/action", "Microsoft.ContainerService/managedClusters/stop/action") 
    | sort by TimeGenerated desc
```

of if you use vmss start/deallocate mode :

```
AzureActivity 
    | filter OperationName in ("Start Virtual Machine Scale Set", "Deallocate Virtual Machine Scale Set") 
    | sort by TimeGenerated desc
```

Or more globally, if you just want to be alerted of the result of the runbook :

```
AzureDiagnostics
    | where (RunbookName_s == "AksStartStop" and ResultType in ('Completed', 'Failed'))
    | project ResourceGroup, ResultType, ResultDescription, RunbookName_s
```

*Replace `AksStartStop` by the name you have given to your runbook*

## Local development

1. Create a virtualenv with python3 and activate it

    ```
    python -m venv .
    . .venv/bin/activate
    ```
   
2. Install requirements

    ```
    pip install -r requirements.txt
    ```
   
3. Setup env variables to authenticate with Azure using a service principal

    ```
    export AZURE_SUBSCRIPTION_ID="XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
    export AZURE_TENANT_ID="XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
    export AZURE_CLIENT_ID="XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
    export AZURE_CLIENT_SECRET="XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
    ```
   
4. Run the script

    ```
    python startstop.py start mycluster --use-vmss --dry-run --auth-mode=environment
    ```