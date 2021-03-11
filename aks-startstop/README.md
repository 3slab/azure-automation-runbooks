# AKS Start/Stop

This is a python3 script to be used in an Azure Automation Runbook in order to automatize AKS start/stop operation.

## Usage

    python startstop.py <clusters> <action> [<dryrun>]
    python startstop.py <clusters> <action> [<vmss>] [<dryrun>]

Script needs 2 mandatory positional arguments :
    * `clusters` : coma separated list of AKS cluster names
    * `action` : start/stop
Other arguments are optionals :
    * `vmss` : if 1 and cluster uses vmss, then instead of calling start/stop on the cluster itself, it
    starts/deallocates vmss instances. Enabled per default.
    * `dryrun` : if 1, then run script in dry run mode

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

## Local development

1. Create a virtualenv with python3 and activate it

    python -m venv .
    . .venv/bin/activate

2. Install requirements

    pip install -r requirements.txt

3. Setup env variables to authenticate with Azure using a service principal

    export AZURE_SUBSCRIPTION_ID="XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
    export AZURE_TENANT_ID="XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
    export AZURE_CLIENT_ID="XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
    export AZURE_CLIENT_SECRET="XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
    export AZURE_AUTH_MODE="local"

4. Run the script

    python startstop.py mycluster start 1 1 
