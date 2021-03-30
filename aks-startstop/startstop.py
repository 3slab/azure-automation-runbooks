#!/usr/bin/env python3

"""
Azure Automation Runbook to start/stop AKS cluster

Usage:

    python startstop.py <action> <clusters> [--use-vmss] [--use-availability-set] [--dry-run] [--disable-check-state]
    [--disable-power-state] [--auth-mode=<auth_mode>]

Script needs 2 mandatory arguments :
    * `clusters` : coma separated list of AKS cluster names
    * `action` : start/stop
Other arguments are optionals :
    * `--use-vmss` : if the cluster uses vmss, then instead of calling start/stop on the cluster itself, it
    starts/deallocates vmss instances.
    * `--use-availability-set` : if the cluster uses availabilityset, then instead of calling start/stop on the cluster
    itself, it starts/deallocates each vm individually
    * `--dry-run` : run script in dry run mode
    * `--disable-check-state` : disable checking if the cluster is in Suceeded state before doing anything
    * `--disable-power-state` : disable checking if the cluster is in running/stopped state before doing anything
    * `--auth-mode=<auth_mode>` : set auth mode (see README in github repo)

Example :

    python startstop.py start k8s-dev1,k8s-dev2
"""

import argparse
import os
import sys
import time
import logging

import automationassets
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.resource import ResourceManagementClient


logging.basicConfig(
    format='%(asctime)s - %(levelname)-7s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

START_ACTION = 'start'
STOP_ACTION = 'stop'
PROFILE_TYPE_VMSS = 'VirtualMachineScaleSets'
PROFILE_TYPE_AVAILABILITYSET = 'AvailabilitySet'

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


def startstop_cluster_with_availabilityset(cluster, operation, dry_run):
    logger.debug('listing availabilityset in resource group {} for cluster {} ...'.format(cluster.node_resource_group,
                                                                                          cluster.name))
    avset_list = list(compute_client.availability_sets.list(cluster.node_resource_group))
    logger.debug('Found {} availabilityset'.format(len(avset_list)))
    for avset in avset_list:
        logger.debug('Stopping {} vm in availabilityset {} ...'.format(len(avset.virtual_machines), avset.name))
        for vm_in_avset in avset.virtual_machines:
            vm = resource_client.resources.get_by_id(vm_in_avset.id, api_version='2021-03-01')
            try:
                if operation == STOP_ACTION:
                    logger.debug('Stopping vm {} ...'.format(vm.name))
                    if not dry_run:
                        compute_client.virtual_machines.begin_deallocate(cluster.node_resource_group,
                                                                         vm.name).result()
                elif operation == START_ACTION:
                    logger.debug('Starting vm {} ...'.format(vm.name))
                    if not dry_run:
                        compute_client.virtual_machines.begin_start(cluster.node_resource_group,
                                                                    vm.name).result()
                logger.debug('vm {} processed'.format(vm.name))
            except Exception as e:
                logger.exception(e)
                return False

    return True


def startstop_cluster_with_vmss(cluster, operation, dry_run):
    """
    Handle start/stop(deallocate) for cluster with VMSS nodepool

    :param cluster: a Azure SDK managedCluster object
    :param operation: START/STOP action command
    :param dry_run: boolean to enable dry_run mode
    :return: True if it succeeded. Exception raised if not.
    """
    logger.debug('listing vmss in resource group {} for cluster {} ...'.format(cluster.node_resource_group,
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
        except Exception as e:
            logger.exception(e)
            return False

    return True


def startstop_cluster_standard_mode(resource_group, cluster, operation, dry_run, check_power_state):
    """
    Handle start/stop for cluster with official start/stop command

    :param resource_group: resource group name where the cluster is located
    :param cluster: a Azure SDK managedCluster object
    :param operation: START/STOP action command
    :param dry_run: boolean to enable dry_run mode
    :param check_power_state: check if the cluster is running or stopped before doing anything
    :return: True if it succeeded. Exception raised if not.
    """
    if check_power_state:
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
    except Exception as e:
        logger.exception(e)
        return False

    return True


def process_cluster(resource_group, cluster, operation, vmss_mode, avset_mode, dry_run, check_state, check_power_state):
    """
    Process start/stop operation on a cluster

    :param resource_group: resource group name where the cluster is located
    :param cluster: a Azure SDK managedCluster object
    :param operation: START/STOP action command
    :param vmss_mode: boolean to enable vmss start/deallocate mode
    :param avset_mode: boolean to enable availabilityset vms start/deallocate mode
    :param dry_run: boolean to enable dry_run mode
    :param check_state: boolean to check if cluster is in Succeeded state before doing anything
    :param check_power_state: check if the cluster is running or stopped before doing anything
    :return: True if it succeeded. Exception raised if not.
    """
    logger.info('processing cluster {} ...'.format(cluster.name))

    container_service_provision_state = cluster.provisioning_state
    if check_state and container_service_provision_state != 'Succeeded':
        logger.error('Unable to perform any operation on a cluster that is not in Succeeded state !')
        return False

    agentpool_profile_type = [profile.type for profile in cluster.agent_pool_profiles]
    cluster_uses_vmss = PROFILE_TYPE_VMSS in agentpool_profile_type
    cluster_uses_availabilityset = PROFILE_TYPE_AVAILABILITYSET in agentpool_profile_type

    if cluster_uses_vmss and vmss_mode:
        return startstop_cluster_with_vmss(cluster, operation, dry_run)
    elif cluster_uses_availabilityset and avset_mode:
        return startstop_cluster_with_availabilityset(cluster, operation, dry_run)
    else:
        return startstop_cluster_standard_mode(resource_group, cluster, operation, dry_run, check_power_state)


def process_resource_group(resource_group, clusters, operation, vmss_mode, avset_mode, dry_run, check_state,
                           check_power_state):
    """
    Look for cluster in a resource group. If cluster in the list, attempt to start/stop it.

    :param resource_group: a AZure SDK resource group object
    :param clusters: a list of cluster names to attempt to start/stop if they are in the group
    :param operation: START/STOP action command
    :param vmss_mode: boolean to enable vmss start/deallocate mode
    :param avset_mode: boolean to enable availabilityset vms start/deallocate mode
    :param dry_run: boolean to enable dry_run mode
    :param check_state: boolean to check if cluster is in Succeeded state before doing anything
    :param check_power_state: check if the cluster is running or stopped before doing anything
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
            result = process_cluster(resource_group_name, container_service, operation, vmss_mode, avset_mode, dry_run,
                                     check_state, check_power_state)
            if result:
                handled_clusters.append(container_service.name)
            else:
                errored_clusters.append(container_service.name)

    if len(errored_clusters) == 0 and len(handled_clusters) == 0:
        logger.info('No cluster to process in resource group')

    return errored_clusters, handled_clusters


def main(clusters, operation, vmss_mode, avset_mode, dry_run, check_state, check_power_state):
    """
    Run on script startup. It list all resource groups in the subscription and starts looking for cluster in them

    :param clusters: a list of cluster names to attempt to start/stop
    :param operation: START/STOP action command
    :param vmss_mode: boolean to enable vmss start/deallocate mode
    :param avset_mode: boolean to enable availabilityset vms start/deallocate mode
    :param dry_run: boolean to enable dry_run mode
    :param check_state: boolean to check if cluster is in Succeeded state before doing anything
    :param check_power_state: check if the cluster is running or stopped before doing anything
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
        error_in_rg, success_in_rg = process_resource_group(resource_group, clusters, operation, vmss_mode, avset_mode,
                                                            dry_run, check_state, check_power_state)
        errored_clusters.extend(error_in_rg)
        handled_clusters.extend(success_in_rg)

    # identify cluster not found in subscription
    not_in_success_clusters = [cluster_name for cluster_name in clusters if cluster_name not in handled_clusters]
    not_in_errored_clusters = [cluster_name for cluster_name in clusters if cluster_name not in errored_clusters]
    unknown_clusters.extend(list(set(not_in_success_clusters).intersection(set(not_in_errored_clusters))))

    return errored_clusters, handled_clusters, unknown_clusters


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='start/stop AKS cluster')
    parser.add_argument('action', choices=[START_ACTION, STOP_ACTION], help='start/stop')
    parser.add_argument('clusters', type=lambda s: [i for i in s.split(',')],
                        help='coma separated list of AKS cluster names')
    parser.add_argument('--use-vmss', action='store_true', default=False,
                        help='if cluster uses vmss, then instead of calling start/stop on the cluster itself, it '
                             'starts/deallocates vmss instances.')
    parser.add_argument('--use-availability-set', action='store_true', default=False,
                        help='if cluster uses availabilityset, then instead of calling start/stop on the cluster '
                             'itself, it starts/deallocates each vm instances one at a time.')
    parser.add_argument('--dry-run', action='store_true', default=False, help='run script in dry run mode')
    parser.add_argument('--disable-check-state', action='store_true', default=False,
                        help='disable checking that the cluster is in succeeded state before doing anything.')
    parser.add_argument('--disable-check-power-state', action='store_true', default=False,
                        help='disable checking that the cluster is already running or stopped.')
    parser.add_argument('--auth-mode', default='automationrunascredentials',
                        choices=['automationrunascredentials', 'automationvariables', 'environment'],
                        help='set how the credentials to authenticate with Azure are loaded')
    args = parser.parse_args()

    action = args.action
    cluster_names = args.clusters
    use_vmss = args.use_vmss
    use_avset = args.use_availability_set
    dry_mode = args.dry_run
    check_state = args.disable_check_state is False
    check_power_state = args.disable_check_power_state is False
    auth_mode = args.auth_mode

    logger.debug('Attempting to {} clusters named {} ...'.format(action, ', '.join(cluster_names)))

    if use_vmss:
        logger.debug('Mode VMSS start/deallocate enabled')
    else:
        logger.debug('Mode VMSS start/deallocate disabled')

    if use_avset:
        logger.debug('Mode AvailabilitySet start/deallocate enabled')
    else:
        logger.debug('Mode AvailabilitySet start/deallocate disabled')

    if dry_mode:
        logger.warning('RUNNING IN DRY MODE !!!!')
    else:
        logger.info('You have 3 seconds to stop the script...')
        time.sleep(3)

    logger.debug('Starting ...')

    if auth_mode == 'automationrunascredentials':
        logger.info('Building credentials to connect with AzureRunAsConnection ...')
        runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
        SUBSCRIPTION_ID = str(runas_connection["SubscriptionId"])
        azure_credential = get_automation_runas_credential(runas_connection)
        logger.debug('Credentials built')
    elif auth_mode == 'automationvariables':
        tenant_id = automationassets.get_automation_variable('External_AksStartStop_TenantId')
        client_id = automationassets.get_automation_variable('External_AksStartStop_ClientId')
        client_secret = automationassets.get_automation_variable('External_AksStartStop_ClientSecret')
        SUBSCRIPTION_ID = automationassets.get_automation_variable('Internal_AzureSubscriptionId')

        if None in [tenant_id, client_id, client_secret, SUBSCRIPTION_ID]:
            logger.error('In automationvariables auth mode, you need to provide the following variables in your '
                         'automation account: External_AksStartStop_TenantId, External_AksStartStop_ClientId, '
                         'External_AksStartStop_ClientSecret, Internal_AzureSubscriptionId')
            exit(1)

        from azure.identity import ClientSecretCredential
        azure_credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    else:
        logger.info('Loading credentials from environment ...')

        SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID", None)
        CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", None)
        CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", None)
        if None in [SUBSCRIPTION_ID, CLIENT_ID, CLIENT_SECRET]:
            logger.error('In environment auth mode, you need to provide the environment variables : '
                         'AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET')
            exit(1)

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
        azure_credential,
        SUBSCRIPTION_ID
    )

    logger.debug('Working in subscription {} ...'.format(SUBSCRIPTION_ID))
    with_error_clusters, processed_clusters, not_found_clusters = main(cluster_names, action, use_vmss, use_avset,
                                                                       dry_mode, check_state, check_power_state)

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
