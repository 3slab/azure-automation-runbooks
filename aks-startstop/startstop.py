#!/usr/bin/env python3

"""
Azure Automation Runbook to start/stop AKS cluster

Usage:

    python startstop.py <clusters> <action> [<vmss>] [<dryrun>] [checkstate]

Script needs 2 mandatory positional arguments :
    * `clusters` : coma separated list of AKS cluster names
    * `action` : start/stop
Other arguments are optionals :
    * `vmss` : if 1 and cluster uses vmss, then instead of calling start/stop on the cluster itself, it
    starts/deallocates vmss instances. Enabled per default.
    * `dryrun` : if 1, then run script in dry run mode
    * `checkstate` : if 1 then check that the cluster is in succeeded state before doing anything.
    Enabled per default

Example :

    python startstop.py k8s-dev1,k8s-dev2 start

Authentication on Azure : per default it uses Azure Automation AzureRunAsCertificate. In local dev
mode, you can override this by providing these environment variables
    * `AZURE_AUTH_MODE` : set any value in this env var to disable automation AzureRunAsCertificate
    * `AZURE_SUBSCRIPTION_ID` : the subscription id where you want to run this script
    * `AZURE_CLIENT_ID` : a client id of an azure service principal with RBAC permission on the subscription
    (Contributor)
    * `AZURE_CLIENT_SECRET` : a client secret of an azure service principal with RBAC permission on the
    subscription (Contributor)
"""

import os
import sys
import time
import logging

import automationassets
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError


logging.basicConfig(
    format='%(asctime)s - %(levelname)-7s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

START_ACTION = 'start'
STOP_ACTION = 'stop'
PROFILE_TYPE_VMSS = 'VirtualMachineScaleSets'

resource_client = None
containerservice_client = None
compute_client = None


def get_automation_runas_credential(runas_connection):
    """ Returns credentials to authenticate against Azure resource manager """
    from OpenSSL import crypto
    from msrestazure import azure_active_directory
    import adal

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    pks12_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pks12_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    resource = "https://management.core.windows.net/"
    authority_url = ("https://login.microsoftonline.com/" + tenant_id)
    context = adal.AuthenticationContext(authority_url)
    return azure_active_directory.AdalAuthentication(
        lambda: context.acquire_token_with_client_certificate(
            resource,
            application_id,
            pem_pkey,
            thumbprint)
    )


def startstop_cluster_with_vmss(cluster, operation, dry_run):
    """
    Handle start/stop(deallocate) for cluster with VMSS nodepool

    :param cluster: a Azure SDK managedCluster object
    :param operation: START/STOP action command
    :param dry_run: boolean to enable dry_run mode
    :return: True if it succeeded. Exception raised if not.
    """
    logger.info('listing vmss in resource group {} for cluster {} ...'.format(cluster.node_resource_group,
                                                                              cluster.name))
    vmss_list = list(compute_client.virtual_machine_scale_sets.list(cluster.node_resource_group))
    logger.debug('Found {} vmss'.format(len(vmss_list)))

    for vmss in vmss_list:
        try:
            if operation == STOP_ACTION:
                logger.debug('Stopping vmss {} ...'.format(vmss.name))
                if not dry_run:
                    compute_client.virtual_machine_scale_sets.begin_deallocate(cluster.node_resource_group,
                                                                               vmss.name).result()
            elif operation == START_ACTION:
                logger.debug('Starting vmss {} ...'.format(vmss.name))
                if not dry_run:
                    compute_client.virtual_machine_scale_sets.begin_start(cluster.node_resource_group,
                                                                          vmss.name).result()
            logger.debug('vmss {} processed'.format(vmss.name))
        except HttpResponseError as e:
            logger.exception(e)
            return False

    return True


def startstop_cluster_standard_mode(resource_group, cluster, operation, dry_run):
    """
    Handle start/stop for cluster with official start/stop command

    :param resource_group: resource group name where the cluster is located
    :param cluster: a Azure SDK managedCluster object
    :param operation: START/STOP action command
    :param dry_run: boolean to enable dry_run mode
    :return: True if it succeeded. Exception raised if not.
    """
    container_service_power_state = cluster.power_state.code

    if operation == START_ACTION and container_service_power_state == 'Running':
        logger.error('Unable to start an already running cluster')
        return False

    if operation == STOP_ACTION and container_service_power_state == 'Stopped':
        logger.debug('Unable to stop an already stopped cluster')
        return False

    try:
        if operation == STOP_ACTION:
            logger.debug('Stopping cluster {} ...'.format(cluster.name))
            if not dry_run:
                containerservice_client.managed_clusters.begin_stop(resource_group, cluster.name).result()
        elif operation == START_ACTION:
            logger.debug('Starting cluster {} ...'.format(cluster.name))
            if not dry_run:
                containerservice_client.managed_clusters.begin_start(resource_group, cluster.name).result()
        logger.debug('cluster {} processed'.format(cluster.name))
    except HttpResponseError as e:
        logger.exception(e)
        return False

    return True


def process_cluster(resource_group, cluster, operation, vmss_mode, dry_run, check_state):
    """
    Process start/stop operation on a cluster

    :param resource_group: resource group name where the cluster is located
    :param cluster: a Azure SDK managedCluster object
    :param operation: START/STOP action command
    :param vmss_mode: boolean to enable vmss start/deallocate mode
    :param dry_run: boolean to enable dry_run mode
    :param check_state: boolean to check if cluster is in Succeeded state before doing anything
    :return: True if it succeeded. Exception raised if not.
    """
    logger.info('processing cluster {} ...'.format(cluster.name))

    container_service_provision_state = cluster.provisioning_state
    if check_state and container_service_provision_state != 'Succeeded':
        logger.error('Unable to perform any operation on a cluster that is not in Succeeded state !')
        return False

    agentpool_profile_type = [profile.type for profile in cluster.agent_pool_profiles]
    cluster_uses_vmss = PROFILE_TYPE_VMSS in agentpool_profile_type

    if cluster_uses_vmss and vmss_mode:
        return startstop_cluster_with_vmss(cluster, operation, dry_run)
    else:
        return startstop_cluster_standard_mode(resource_group, cluster, operation, dry_run)


def process_resource_group(resource_group, clusters, operation, vmss_mode, dry_run, check_state):
    """
    Look for cluster in a resource group. If cluster in the list, attempt to start/stop it.

    :param resource_group: a AZure SDK resource group object
    :param clusters: a list of cluster names to attempt to start/stop if they are in the group
    :param operation: START/STOP action command
    :param vmss_mode: boolean to enable vmss start/deallocate mode
    :param dry_run: boolean to enable dry_run mode
    :param check_state: boolean to check if cluster is in Succeeded state before doing anything
    :return: 2 lists
        first one of all cluster names where a start/stop operation was attempted but resulted in an error
        second one of all cluster names where a start/stop operation was attempted and succeeded
    """
    handled_clusters = []
    errored_clusters = []

    resource_group_name = resource_group.name

    logger.info('Processing rg {} ...'.format(resource_group_name))

    # list managed clusters in rg
    logger.info('Loading AKS cluster in resource group {} ...'.format(resource_group_name))
    container_services = list(containerservice_client.managed_clusters.list_by_resource_group(resource_group_name))
    to_process_services = [container_service for container_service in container_services
                           if container_service.name in clusters]
    logger.debug('{} clusters to process among {}'.format(len(to_process_services), len(container_services)))

    for container_service in to_process_services:
        # if cluster has the correct name, process the action and store the result
        if container_service.name in clusters:
            result = process_cluster(resource_group_name, container_service, operation, vmss_mode, dry_run, check_state)
            if result:
                handled_clusters.append(container_service.name)
            else:
                errored_clusters.append(container_service.name)

    if len(errored_clusters) == 0 and len(handled_clusters) == 0:
        logger.info('No cluster to process in resource group')

    return errored_clusters, handled_clusters


def main(clusters, operation, vmss_mode, dry_run, check_state):
    """
    Run on script startup. It list all resource groups in the subscription and starts looking for cluster in them

    :param clusters: a list of cluster names to attempt to start/stop
    :param operation: START/STOP action command
    :param vmss_mode: boolean to enable vmss start/deallocate mode
    :param dry_run: boolean to enable dry_run mode
    :param check_state: boolean to check if cluster is in Succeeded state before doing anything
    :return: 3 lists
        first one of all cluster names where a start/stop operation was attempted but resulted in an error
        second one of all cluster names where a start/stop operation was attempted and succeeded
        third one of all cluster names not found in any resource group of the subscription
    """
    handled_clusters = []
    errored_clusters = []
    unknown_clusters = []

    # list rg in subscription
    logger.info('Loading resource groups list ...')
    resource_groups = list(resource_client.resource_groups.list())
    logger.debug('Found {} resource groups'.format(len(resource_groups)))

    # process clusters in each rg
    for resource_group in resource_groups:
        error_in_rg, success_in_rg = process_resource_group(resource_group, clusters, operation, vmss_mode, dry_run,
                                                            check_state)
        errored_clusters.extend(error_in_rg)
        handled_clusters.extend(success_in_rg)

    # identify cluster not found in subscription
    not_in_success_clusters = [cluster_name for cluster_name in clusters if cluster_name not in handled_clusters]
    not_in_errored_clusters = [cluster_name for cluster_name in clusters if cluster_name not in errored_clusters]
    unknown_clusters.extend(list(set(not_in_success_clusters).intersection(set(not_in_errored_clusters))))

    return errored_clusters, handled_clusters, unknown_clusters


if __name__ == "__main__":
    if len(sys.argv) < 3:
        logger.error('Start/stop scripts need 2 mandatory positional arguments')
        exit(1)

    cluster_names = str(sys.argv[1]).split(',')
    if len(cluster_names) == 0:
        logger.error('No cluster names provided as first argument of the script')
        exit(1)

    action = str(sys.argv[2])
    if action not in [START_ACTION, STOP_ACTION]:
        logger.error('Action argument can only take two values : start or stop')
        exit(1)

    logger.debug('Attempting to {} clusters named {} ...'.format(action, ', '.join(cluster_names)))

    use_vmss = True
    dry_mode = False
    check_state = True
    if len(sys.argv) > 3:
        use_vmss = str(sys.argv[3]) == '1'
    if len(sys.argv) > 4:
        dry_mode = str(sys.argv[4]) == '1'
    if len(sys.argv) > 5:
        check_state = str(sys.argv[5]) == '1'

    if use_vmss:
        logger.debug('Mode VMSS start/deallocate enabled')
    else:
        logger.debug('Mode VMSS start/deallocate disabled')

    if dry_mode:
        logger.warning('RUNNING IN DRY MODE !!!!')
    else:
        logger.info('You have 3 seconds to stop the script...')
        time.sleep(3)

    logger.debug('Starting ...')

    AUTH_MODE = os.environ.get("AZURE_AUTH_MODE", 'automationassets')

    SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID", None)
    CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", None)
    CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", None)

    if AUTH_MODE != 'automationassets' and None in [SUBSCRIPTION_ID, CLIENT_ID, CLIENT_SECRET]:
        logger.error('Outside Azure Automation environment, you need to provide the environment variables : '
                     'AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET')
        exit(1)

    # override credentials when runing in automationassets
    if AUTH_MODE == 'automationassets':
        logger.info('Building credentials to connect with AzureRunAsConnection ...')
        runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
        subscription_id = str(runas_connection["SubscriptionId"])
        azure_credential = get_automation_runas_credential(runas_connection)
        logger.debug('Credentials built')
    else:
        logger.info('Loading credentials from environment ...')
        from azure.identity import DefaultAzureCredential
        azure_credential = DefaultAzureCredential()
        logger.debug('Credentials loaded (but without verification they exist)')

    # instantiate clients
    resource_client = ResourceManagementClient(
        azure_credential,
        SUBSCRIPTION_ID
    )

    containerservice_client = ContainerServiceClient(
        azure_credential,
        SUBSCRIPTION_ID
    )

    compute_client = ComputeManagementClient(
        credential=azure_credential,
        subscription_id=SUBSCRIPTION_ID
    )

    logger.debug('Working in subscription {} ...'.format(SUBSCRIPTION_ID))
    with_error_clusters, processed_clusters, not_found_clusters = main(cluster_names, action, use_vmss, dry_mode,
                                                                       check_state)

    if len(processed_clusters) > 0:
        logger.info('Clusters {} processed'.format(', '.join(processed_clusters)))

    if len(with_error_clusters) > 0:
        logger.error('Clusters {} not processed because of errors'.format(', '.join(with_error_clusters)))

    if len(not_found_clusters) > 0:
        logger.error('Clusters {} not found'.format(', '.join(not_found_clusters)))

    if len(with_error_clusters) > 0 or len(not_found_clusters) > 0:
        logger.debug('Ended with errors')
        exit(1)

    logger.debug('Success')
