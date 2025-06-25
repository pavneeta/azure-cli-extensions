# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=too-many-lines, disable=broad-except
import datetime
import json
import os
import os.path
import platform
import ssl
import sys
import threading
import time
import webbrowser

from azext_aks_preview._client_factory import (
    CUSTOM_MGMT_AKS_PREVIEW,
    cf_agent_pools,
    get_compute_client,
)
from azext_aks_preview._consts import (
    ADDONS,
    ADDONS_DESCRIPTIONS,
    CONST_ACC_SGX_QUOTE_HELPER_ENABLED,
    CONST_AZURE_KEYVAULT_SECRETS_PROVIDER_ADDON_NAME,
    CONST_CONFCOM_ADDON_NAME,
    CONST_INGRESS_APPGW_ADDON_NAME,
    CONST_INGRESS_APPGW_APPLICATION_GATEWAY_ID,
    CONST_INGRESS_APPGW_APPLICATION_GATEWAY_NAME,
    CONST_INGRESS_APPGW_SUBNET_CIDR,
    CONST_INGRESS_APPGW_SUBNET_ID,
    CONST_INGRESS_APPGW_WATCH_NAMESPACE,
    CONST_KUBE_DASHBOARD_ADDON_NAME,
    CONST_MONITORING_ADDON_NAME,
    CONST_MONITORING_LOG_ANALYTICS_WORKSPACE_RESOURCE_ID,
    CONST_MONITORING_USING_AAD_MSI_AUTH,
    CONST_NODEPOOL_MODE_USER,
    CONST_OPEN_SERVICE_MESH_ADDON_NAME,
    CONST_ROTATION_POLL_INTERVAL,
    CONST_SCALE_DOWN_MODE_DELETE,
    CONST_SCALE_SET_PRIORITY_REGULAR,
    CONST_SECRET_ROTATION_ENABLED,
    CONST_SPOT_EVICTION_POLICY_DELETE,
    CONST_VIRTUAL_NODE_ADDON_NAME,
    CONST_VIRTUAL_NODE_SUBNET_NAME,
    CONST_AZURE_SERVICE_MESH_MODE_ISTIO,
    CONST_AZURE_SERVICE_MESH_UPGRADE_COMMAND_START,
    CONST_AZURE_SERVICE_MESH_UPGRADE_COMMAND_COMPLETE,
    CONST_AZURE_SERVICE_MESH_UPGRADE_COMMAND_ROLLBACK,
    CONST_SSH_ACCESS_LOCALUSER,
    CONST_NODE_PROVISIONING_STATE_SUCCEEDED,
    CONST_DEFAULT_NODE_OS_TYPE,
    CONST_VIRTUAL_MACHINE_SCALE_SETS,
    CONST_VIRTUAL_MACHINES,
    CONST_AVAILABILITY_SET,
    CONST_MIN_NODE_IMAGE_VERSION,
    CONST_ARTIFACT_SOURCE_DIRECT,
    CONST_K8S_EXTENSION_CUSTOM_MOD_NAME,
    CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME,
)
from azext_aks_preview._helpers import (
    check_is_private_link_cluster,
    get_cluster_snapshot_by_snapshot_id,
    get_k8s_extension_module,
    get_nodepool_snapshot_by_snapshot_id,
    print_or_merge_credentials,
    process_message_for_run_command,
    check_is_monitoring_addon_enabled,
    get_all_extension_types_in_allow_list,
    get_all_extensions_in_allow_list,
    raise_validation_error_if_extension_type_not_in_allow_list,
    get_extension_in_allow_list,
)
from azext_aks_preview._podidentity import (
    _ensure_managed_identity_operator_permission,
    _ensure_pod_identity_addon_is_enabled,
    _fill_defaults_for_pod_identity_profile,
    _update_addon_pod_identity,
)
from azext_aks_preview._resourcegroup import get_rg_location
from azext_aks_preview.addonconfiguration import (
    add_ingress_appgw_addon_role_assignment,
    add_virtual_node_role_assignment,
    enable_addons,
)
from azext_aks_preview.aks_diagnostics import aks_kanalyze_cmd, aks_kollect_cmd
from azext_aks_preview.aks_draft.commands import (
    aks_draft_cmd_create,
    aks_draft_cmd_generate_workflow,
    aks_draft_cmd_setup_gh,
    aks_draft_cmd_up,
    aks_draft_cmd_update,
)
from azext_aks_preview.maintenanceconfiguration import (
    aks_maintenanceconfiguration_update_internal,
)
from azext_aks_preview.managednamespace import (
    aks_managed_namespace_add,
    aks_managed_namespace_update,
)
from azure.cli.command_modules.acs._helpers import (
    get_user_assigned_identity_by_resource_id
)
from azure.cli.command_modules.acs._validators import (
    extract_comma_separated_string,
)
from azure.cli.command_modules.acs.addonconfiguration import (
    ensure_container_insights_for_monitoring,
    ensure_default_log_analytics_workspace_for_monitoring,
    sanitize_loganalytics_ws_resource_id,
)
from azure.cli.core.api import get_config_dir
from azure.cli.core.azclierror import (
    ArgumentUsageError,
    ClientRequestError,
    InvalidArgumentValueError,
    MutuallyExclusiveArgumentError,
    RequiredArgumentMissingError,
    ValidationError,
)
from azure.cli.core.commands import LongRunningOperation
from azure.cli.core.commands.client_factory import (
    get_subscription_id,
    get_mgmt_service_client,
)
from azure.cli.core.profiles import ResourceType
from azure.cli.core.util import (
    in_cloud_console,
    sdk_no_wait,
    shell_safe_json_parse,
)
from azure.core.exceptions import (
    ResourceNotFoundError,
    HttpResponseError,
)
from dateutil.parser import parse
from knack.log import get_logger
from knack.prompting import prompt_y_n
from knack.util import CLIError
from six.moves.urllib.error import URLError
from six.moves.urllib.request import urlopen

logger = get_logger(__name__)


def wait_then_open(url):
    """
    Waits for a bit then opens a URL.  Useful for waiting for a proxy to come up, and then open the URL.
    """
    for _ in range(1, 10):
        try:
            with urlopen(url, context=_ssl_context()):
                break
        except URLError:
            time.sleep(1)
    webbrowser.open_new_tab(url)


def wait_then_open_async(url):
    """
    Spawns a thread that waits for a bit then opens a URL.
    """
    t = threading.Thread(target=wait_then_open, args=url)
    t.daemon = True
    t.start()


def _ssl_context():
    if sys.version_info < (3, 4) or (in_cloud_console() and platform.system() == 'Windows'):
        try:
            # added in python 2.7.13 and 3.6
            return ssl.SSLContext(ssl.PROTOCOL_TLS)
        except AttributeError:
            return ssl.SSLContext(ssl.PROTOCOL_TLSv1)

    return ssl.create_default_context()


# pylint: disable=too-many-locals
def store_acs_service_principal(subscription_id, client_secret, service_principal,
                                file_name='acsServicePrincipal.json'):
    obj = {}
    if client_secret:
        obj['client_secret'] = client_secret
    if service_principal:
        obj['service_principal'] = service_principal

    config_path = os.path.join(get_config_dir(), file_name)
    full_config = load_service_principals(config_path=config_path)
    if not full_config:
        full_config = {}
    full_config[subscription_id] = obj

    with os.fdopen(os.open(config_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600),
                   'w+') as spFile:
        json.dump(full_config, spFile)


def load_acs_service_principal(subscription_id, file_name='acsServicePrincipal.json'):
    config_path = os.path.join(get_config_dir(), file_name)
    config = load_service_principals(config_path)
    if not config:
        return None
    return config.get(subscription_id)


def load_service_principals(config_path):
    if not os.path.exists(config_path):
        return None
    fd = os.open(config_path, os.O_RDONLY)
    try:
        with os.fdopen(fd) as f:
            return shell_safe_json_parse(f.read())
    except:  # pylint: disable=bare-except
        return None


def aks_browse(
    cmd,
    client,
    resource_group_name,
    name,
    disable_browser=False,
    listen_address="127.0.0.1",
    listen_port="8001",
):
    from azure.cli.command_modules.acs.custom import _aks_browse

    return _aks_browse(
        cmd,
        client,
        resource_group_name,
        name,
        disable_browser,
        listen_address,
        listen_port,
        CUSTOM_MGMT_AKS_PREVIEW,
    )


# pylint: disable=unused-argument
def aks_namespace_add(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    name,
    cpu_request,
    cpu_limit,
    memory_request,
    memory_limit,
    tags=None,
    labels=None,
    annotations=None,
    aks_custom_headers=None,
    ingress_policy=None,
    egress_policy=None,
    adoption_policy=None,
    delete_policy=None,
    no_wait=False,
):
    existedNamespace = None
    try:
        existedNamespace = client.get(resource_group_name, cluster_name, name)
    except ResourceNotFoundError:
        pass

    if existedNamespace:
        raise ClientRequestError(
            f"Namespace '{name}' already exists. Please use 'az aks namespace update' to update it."
        )

    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    headers = get_aks_custom_headers(aks_custom_headers)
    return aks_managed_namespace_add(cmd, client, raw_parameters, headers, no_wait)


# pylint: disable=unused-argument
def aks_namespace_update(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    name,
    cpu_request=None,
    cpu_limit=None,
    memory_request=None,
    memory_limit=None,
    tags=None,
    labels=None,
    annotations=None,
    aks_custom_headers=None,
    ingress_policy=None,
    egress_policy=None,
    adoption_policy=None,
    delete_policy=None,
    no_wait=False,
):
    try:
        existedNamespace = client.get(resource_group_name, cluster_name, name)
    except ResourceNotFoundError:
        raise ClientRequestError(
            f"Namespace '{name}' doesn't exist."
            "Please use 'aks namespace list' to get current list of managed namespaces"
        )

    if existedNamespace:
        # DO NOT MOVE: get all the original parameters and save them as a dictionary
        raw_parameters = locals()
        headers = get_aks_custom_headers(aks_custom_headers)
        return aks_managed_namespace_update(cmd, client, raw_parameters, headers, existedNamespace, no_wait)


def aks_namespace_show(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, managed_namespace_name: %s ',
                   resource_group_name, cluster_name, name)
    return client.get(resource_group_name, cluster_name, name)


def aks_namespace_list(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name=None,
    cluster_name=None,
):
    if resource_group_name and cluster_name:
        return client.list_by_managed_cluster(resource_group_name, cluster_name)
    rcf = get_mgmt_service_client(cmd.cli_ctx, ResourceType.MGMT_RESOURCE_RESOURCES)
    full_resource_type = "Microsoft.ContainerService/managedClusters/managedNamespaces"
    filters = [f"resourceType eq '{full_resource_type}'"]
    if resource_group_name:
        filters.append(f"resourceGroup eq '{resource_group_name}'")
    odata_filter = " and ".join(filters)
    expand = "createdTime,changedTime,provisioningState"
    resources = rcf.resources.list(filter=odata_filter, expand=expand)
    return list(resources)


def aks_namespace_delete(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    name,
    no_wait=False,
):
    namespace_exists = False
    namespace_instances = client.list_by_managed_cluster(resource_group_name, cluster_name)
    for instance in namespace_instances:
        if instance.name.lower() == name.lower():
            namespace_exists = True
            break

    if not namespace_exists:
        raise ClientRequestError(
            f"Managed namespace {name} doesn't exist, "
            "use 'aks namespace list' to get current managed namespace list"
        )

    return sdk_no_wait(
        no_wait,
        client.begin_delete,
        resource_group_name,
        cluster_name,
        name,
    )


def aks_namespace_get_credentials(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    name,
    path=os.path.join(os.path.expanduser("~"), ".kube", "config"),
    overwrite_existing=False,
    context_name=None,
):
    credentialResults = None
    credentialResults = client.list_credential(resource_group_name, cluster_name, name)

    # Check if KUBECONFIG environmental variable is set
    # If path is different than default then that means -f/--file is passed
    # in which case we ignore the KUBECONFIG variable
    # KUBECONFIG can be colon separated. If we find that condition, use the first entry
    if "KUBECONFIG" in os.environ and path == os.path.join(os.path.expanduser('~'), '.kube', 'config'):
        kubeconfig_path = os.environ["KUBECONFIG"].split(os.pathsep)[0]
        if kubeconfig_path:
            logger.info("The default path '%s' is replaced by '%s' defined in KUBECONFIG.", path, kubeconfig_path)
            path = kubeconfig_path
        else:
            logger.warning("Invalid path '%s' defined in KUBECONFIG.", kubeconfig_path)

    if not credentialResults:
        raise CLIError("No Kubernetes credentials found.")
    try:
        kubeconfig = credentialResults.kubeconfigs[0].value.decode(
            encoding='UTF-8')
        print_or_merge_credentials(
            path, kubeconfig, overwrite_existing, context_name)
    except (IndexError, ValueError) as exc:
        raise CLIError("Fail to find kubeconfig file.") from exc


def aks_maintenanceconfiguration_list(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name
):
    return client.list_by_managed_cluster(resource_group_name, cluster_name)


def aks_maintenanceconfiguration_show(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    config_name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, config_name: %s ',
                   resource_group_name, cluster_name, config_name)
    return client.get(resource_group_name, cluster_name, config_name)


def aks_maintenanceconfiguration_delete(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    config_name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, config_name: %s ',
                   resource_group_name, cluster_name, config_name)
    return client.delete(resource_group_name, cluster_name, config_name)


# pylint: disable=unused-argument
def aks_maintenanceconfiguration_add(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    config_name,
    config_file=None,
    weekday=None,
    start_hour=None,
    schedule_type=None,
    interval_days=None,
    interval_weeks=None,
    interval_months=None,
    day_of_week=None,
    day_of_month=None,
    week_index=None,
    duration_hours=None,
    utc_offset=None,
    start_date=None,
    start_time=None
):
    configs = client.list_by_managed_cluster(resource_group_name, cluster_name)
    for config in configs:
        if config.name == config_name:
            raise CLIError(
                f"Maintenance configuration '{config_name}' already exists, please try a different name, "
                "use 'aks maintenanceconfiguration list' to get current list of maitenance configurations"
            )
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    return aks_maintenanceconfiguration_update_internal(cmd, client, raw_parameters)


def aks_maintenanceconfiguration_update(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    config_name,
    config_file=None,
    weekday=None,
    start_hour=None,
    schedule_type=None,
    interval_days=None,
    interval_weeks=None,
    interval_months=None,
    day_of_week=None,
    day_of_month=None,
    week_index=None,
    duration_hours=None,
    utc_offset=None,
    start_date=None,
    start_time=None
):
    configs = client.list_by_managed_cluster(resource_group_name, cluster_name)
    found = False
    for config in configs:
        if config.name == config_name:
            found = True
            break
    if not found:
        raise CLIError(
            f"Maintenance configuration '{config_name}' doesn't exist."
            "use 'aks maintenanceconfiguration list' to get current list of maitenance configurations"
        )
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    return aks_maintenanceconfiguration_update_internal(cmd, client, raw_parameters)


# pylint: disable=too-many-locals, unused-argument
def aks_create(
    cmd,
    client,
    resource_group_name,
    name,
    ssh_key_value,
    location=None,
    kubernetes_version="",
    tags=None,
    dns_name_prefix=None,
    node_osdisk_diskencryptionset_id=None,
    disable_local_accounts=False,
    disable_rbac=None,
    edge_zone=None,
    admin_username="azureuser",
    generate_ssh_keys=False,
    no_ssh_key=False,
    pod_cidr=None,
    service_cidr=None,
    dns_service_ip=None,
    docker_bridge_address=None,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    fqdn_subdomain=None,
    api_server_authorized_ip_ranges=None,
    enable_private_cluster=False,
    private_dns_zone=None,
    disable_public_fqdn=False,
    service_principal=None,
    client_secret=None,
    enable_managed_identity=None,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    windows_admin_username=None,
    windows_admin_password=None,
    enable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    skip_subnet_role_assignment=False,
    node_resource_group=None,
    k8s_support_plan=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    defender_config=None,
    disk_driver_version=None,
    disable_disk_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    bootstrap_artifact_source=CONST_ARTIFACT_SOURCE_DIRECT,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_addons=None,  # pylint: disable=redefined-outer-name
    workspace_resource_id=None,
    enable_msi_auth_for_monitoring=True,
    enable_syslog=False,
    data_collection_settings=None,
    ampls_resource_id=None,
    enable_high_log_scale_mode=False,
    aci_subnet_name=None,
    appgw_name=None,
    appgw_subnet_cidr=None,
    appgw_id=None,
    appgw_subnet_id=None,
    appgw_watch_namespace=None,
    enable_sgxquotehelper=False,
    enable_secret_rotation=False,
    rotation_poll_interval=None,
    enable_app_routing=False,
    app_routing_default_nginx_controller=None,
    # nodepool paramerters
    nodepool_name="nodepool1",
    node_vm_size=None,
    os_sku=None,
    snapshot_id=None,
    vnet_subnet_id=None,
    pod_subnet_id=None,
    pod_ip_allocation_mode=None,
    enable_node_public_ip=False,
    node_public_ip_prefix_id=None,
    enable_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    node_count=3,
    nodepool_tags=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    node_osdisk_type=None,
    node_osdisk_size=0,
    vm_set_type=None,
    zones=None,
    ppg=None,
    max_pods=0,
    enable_encryption_at_host=False,
    enable_ultra_ssd=False,
    enable_fips_image=False,
    kubelet_config=None,
    linux_os_config=None,
    host_group_id=None,
    gpu_instance_profile=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ip_families=None,
    pod_cidrs=None,
    service_cidrs=None,
    load_balancer_managed_outbound_ipv6_count=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    enable_workload_identity=False,
    enable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    cluster_snapshot_id=None,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    dns_zone_resource_id=None,
    dns_zone_resource_ids=None,
    enable_keda=False,
    enable_vpa=False,
    enable_optimized_addon_scaling=False,
    enable_cilium_dataplane=False,
    custom_ca_trust_certificates=None,
    # advanced networking
    enable_acns=None,
    disable_acns=None,
    disable_acns_observability=None,
    disable_acns_security=None,
    acns_advanced_networkpolicies=None,
    acns_transit_encryption_type=None,
    enable_retina_flow_logs=None,
    # nodepool
    crg_id=None,
    message_of_the_day=None,
    workload_runtime=None,
    enable_custom_ca_trust=False,
    nodepool_allowed_host_ports=None,
    nodepool_asg_ids=None,
    node_public_ip_tags=None,
    # safeguards parameters
    safeguards_level=None,
    safeguards_version=None,
    safeguards_excluded_ns=None,
    # azure service mesh
    enable_azure_service_mesh=None,
    revision=None,
    # azure monitor profile - metrics
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    ssh_access=CONST_SSH_ACCESS_LOCALUSER,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    # validation for existing cluster
    existing_mc = None
    try:
        existing_mc = client.get(resource_group_name, name)
    # pylint: disable=broad-except
    except Exception as ex:
        logger.debug("failed to get cluster, error: %s", ex)
    if existing_mc:
        raise ClientRequestError(
            f"The cluster '{name}' under resource group '{resource_group_name}' already exists. "
            "Please use command 'az aks update' to update the existing cluster, "
            "or select a different cluster name to create a new cluster."
        )

    # decorator pattern
    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterCreateDecorator
    aks_create_decorator = AKSPreviewManagedClusterCreateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # construct mc profile
        mc = aks_create_decorator.construct_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None

    # send request to create a real managed cluster
    return aks_create_decorator.create_mc(mc)


# pylint: disable=too-many-locals, unused-argument
def aks_update(
    cmd,
    client,
    resource_group_name,
    name,
    tags=None,
    disable_local_accounts=False,
    enable_local_accounts=False,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    enable_force_upgrade=False,
    disable_force_upgrade=False,
    upgrade_override_until=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    api_server_authorized_ip_ranges=None,
    enable_public_fqdn=False,
    disable_public_fqdn=False,
    enable_managed_identity=False,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    disable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    k8s_support_plan=None,
    windows_admin_password=None,
    enable_ahub=False,
    disable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    detach_acr=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    disable_defender=False,
    defender_config=None,
    enable_disk_driver=False,
    disk_driver_version=None,
    disable_disk_driver=False,
    enable_file_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_blob_driver=None,
    enable_snapshot_controller=False,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    disable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    disable_http_proxy=False,
    enable_http_proxy=False,
    bootstrap_artifact_source=None,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_secret_rotation=False,
    disable_secret_rotation=False,
    rotation_poll_interval=None,
    # nodepool paramerters
    enable_cluster_autoscaler=False,
    disable_cluster_autoscaler=False,
    update_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ssh_key_value=None,
    load_balancer_managed_outbound_ipv6_count=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    ip_families=None,
    pod_cidr=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    disable_pod_identity=False,
    enable_workload_identity=False,
    disable_workload_identity=False,
    enable_image_cleaner=False,
    disable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    disable_image_integrity=False,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    enable_keda=False,
    disable_keda=False,
    enable_private_cluster=False,
    disable_private_cluster=False,
    private_dns_zone=None,
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    # validation for existing cluster
    existing_mc = None
    try:
        existing_mc = client.get(resource_group_name, name)
    # pylint: disable=broad-except
    except Exception as ex:
        logger.debug("failed to get cluster, error: %s", ex)
    if existing_mc:
        raise ClientRequestError(
            f"The cluster '{name}' under resource group '{resource_group_name}' already exists. "
            "Please use command 'az aks update' to update the existing cluster, "
            "or select a different cluster name to create a new cluster."
        )

    # decorator pattern
    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterCreateDecorator
    aks_create_decorator = AKSPreviewManagedClusterCreateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # construct mc profile
        mc = aks_create_decorator.construct_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None

    # send request to create a real managed cluster
    return aks_create_decorator.create_mc(mc)


# pylint: disable=too-many-locals, unused-argument
def aks_update(
    cmd,
    client,
    resource_group_name,
    name,
    tags=None,
    disable_local_accounts=False,
    enable_local_accounts=False,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    enable_force_upgrade=False,
    disable_force_upgrade=False,
    upgrade_override_until=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    api_server_authorized_ip_ranges=None,
    enable_public_fqdn=False,
    disable_public_fqdn=False,
    enable_managed_identity=False,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    disable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    k8s_support_plan=None,
    windows_admin_password=None,
    enable_ahub=False,
    disable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    detach_acr=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    disable_defender=False,
    defender_config=None,
    enable_disk_driver=False,
    disk_driver_version=None,
    disable_disk_driver=False,
    enable_file_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_blob_driver=None,
    enable_snapshot_controller=False,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    disable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    disable_http_proxy=False,
    enable_http_proxy=False,
    bootstrap_artifact_source=None,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_secret_rotation=False,
    disable_secret_rotation=False,
    rotation_poll_interval=None,
    # nodepool paramerters
    enable_cluster_autoscaler=False,
    disable_cluster_autoscaler=False,
    update_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ssh_key_value=None,
    load_balancer_managed_outbound_ipv6_count=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    ip_families=None,
    pod_cidr=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    disable_pod_identity=False,
    enable_workload_identity=False,
    disable_workload_identity=False,
    enable_image_cleaner=False,
    disable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    disable_image_integrity=False,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    enable_keda=False,
    disable_keda=False,
    enable_private_cluster=False,
    disable_private_cluster=False,
    private_dns_zone=None,
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    # validation for existing cluster
    existing_mc = None
    try:
        existing_mc = client.get(resource_group_name, name)
    # pylint: disable=broad-except
    except Exception as ex:
        logger.debug("failed to get cluster, error: %s", ex)
    if existing_mc:
        raise ClientRequestError(
            f"The cluster '{name}' under resource group '{resource_group_name}' already exists. "
            "Please use command 'az aks update' to update the existing cluster, "
            "or select a different cluster name to create a new cluster."
        )

    # decorator pattern
    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterCreateDecorator
    aks_create_decorator = AKSPreviewManagedClusterCreateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # construct mc profile
        mc = aks_create_decorator.construct_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None

    # send request to create a real managed cluster
    return aks_create_decorator.create_mc(mc)


# pylint: disable=too-many-locals, unused-argument
def aks_update(
    cmd,
    client,
    resource_group_name,
    name,
    tags=None,
    disable_local_accounts=False,
    enable_local_accounts=False,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    enable_force_upgrade=False,
    disable_force_upgrade=False,
    upgrade_override_until=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    api_server_authorized_ip_ranges=None,
    enable_public_fqdn=False,
    disable_public_fqdn=False,
    enable_managed_identity=False,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    disable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    k8s_support_plan=None,
    windows_admin_password=None,
    enable_ahub=False,
    disable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    detach_acr=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    disable_defender=False,
    defender_config=None,
    enable_disk_driver=False,
    disk_driver_version=None,
    disable_disk_driver=False,
    enable_file_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_blob_driver=None,
    enable_snapshot_controller=False,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    disable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    disable_http_proxy=False,
    enable_http_proxy=False,
    bootstrap_artifact_source=None,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_secret_rotation=False,
    disable_secret_rotation=False,
    rotation_poll_interval=None,
    # nodepool paramerters
    enable_cluster_autoscaler=False,
    disable_cluster_autoscaler=False,
    update_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ssh_key_value=None,
    load_balancer_managed_outbound_ipv6_count=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    ip_families=None,
    pod_cidr=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    disable_pod_identity=False,
    enable_workload_identity=False,
    disable_workload_identity=False,
    enable_image_cleaner=False,
    disable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    disable_image_integrity=False,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    enable_keda=False,
    disable_keda=False,
    enable_private_cluster=False,
    disable_private_cluster=False,
    private_dns_zone=None,
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    # validation for existing cluster
    existing_mc = None
    try:
        existing_mc = client.get(resource_group_name, name)
    # pylint: disable=broad-except
    except Exception as ex:
        logger.debug("failed to get cluster, error: %s", ex)
    if existing_mc:
        raise ClientRequestError(
            f"The cluster '{name}' under resource group '{resource_group_name}' already exists. "
            "Please use command 'az aks update' to update the existing cluster, "
            "or select a different cluster name to create a new cluster."
        )

    # decorator pattern
    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterCreateDecorator
    aks_create_decorator = AKSPreviewManagedClusterCreateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # construct mc profile
        mc = aks_create_decorator.construct_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None

    # send request to create a real managed cluster
    return aks_create_decorator.create_mc(mc)


# pylint: disable=too-many-locals, unused-argument
def aks_update(
    cmd,
    client,
    resource_group_name,
    name,
    tags=None,
    disable_local_accounts=False,
    enable_local_accounts=False,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    enable_force_upgrade=False,
    disable_force_upgrade=False,
    upgrade_override_until=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    api_server_authorized_ip_ranges=None,
    enable_public_fqdn=False,
    disable_public_fqdn=False,
    enable_managed_identity=False,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    disable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    k8s_support_plan=None,
    windows_admin_password=None,
    enable_ahub=False,
    disable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    detach_acr=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    disable_defender=False,
    defender_config=None,
    enable_disk_driver=False,
    disk_driver_version=None,
    disable_disk_driver=False,
    enable_file_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_blob_driver=None,
    enable_snapshot_controller=False,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    disable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    disable_http_proxy=False,
    enable_http_proxy=False,
    bootstrap_artifact_source=None,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_secret_rotation=False,
    disable_secret_rotation=False,
    rotation_poll_interval=None,
    # nodepool paramerters
    enable_cluster_autoscaler=False,
    disable_cluster_autoscaler=False,
    update_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ssh_key_value=None,
    load_balancer_managed_outbound_ipv6_count=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    ip_families=None,
    pod_cidr=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    disable_pod_identity=False,
    enable_workload_identity=False,
    disable_workload_identity=False,
    enable_image_cleaner=False,
    disable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    disable_image_integrity=False,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    enable_keda=False,
    disable_keda=False,
    enable_private_cluster=False,
    disable_private_cluster=False,
    private_dns_zone=None,
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterUpdateDecorator

    # decorator pattern
    aks_update_decorator = AKSPreviewManagedClusterUpdateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # update mc profile
        mc = aks_update_decorator.update_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None
    # send request to update the real managed cluster
    return aks_update_decorator.update_mc(mc)


# pylint: disable=unused-argument
def aks_show(cmd, client, resource_group_name, name, aks_custom_headers=None):
    headers = get_aks_custom_headers(aks_custom_headers)
    mc = client.get(resource_group_name, name, headers=headers)
    return _remove_nulls([mc])[0]


# pylint: disable=unused-argument
def aks_stop(cmd, client, resource_group_name, name, no_wait=False):
    instance = client.get(resource_group_name, name)
    # print warning when stopping a private cluster
    if check_is_private_link_cluster(instance):
        logger.warning(
            "Your private cluster apiserver IP might get changed when it's stopped and started.\n"
            "Any user provisioned private endpoints linked to this private cluster will need to be deleted and "
            "created again. Any user managed DNS record also needs to be updated with the new IP."
        )
    return sdk_no_wait(no_wait, client.begin_stop, resource_group_name, name)


# pylint: disable=unused-argument
def aks_list(cmd, client, resource_group_name=None):
    if resource_group_name:
        managed_clusters = client.list_by_resource_group(resource_group_name)
    else:
        managed_clusters = client.list()
    return _remove_nulls(list(managed_clusters))


def _remove_nulls(managed_clusters):
    """
    Remove some often-empty fields from a list of ManagedClusters, so the JSON representation
    doesn't contain distracting null fields.

    This works around a quirk of the SDK for python behavior. These fields are not sent
    by the server, but get recreated by the CLI's own "to_dict" serialization.
    """
    attrs = ['tags']
    ap_attrs = ['os_disk_size_gb', 'vnet_subnet_id']
    sp_attrs = ['secret']
    for managed_cluster in managed_clusters:
        for attr in attrs:
            if getattr(managed_cluster, attr, None) is None:
                delattr(managed_cluster, attr)
        if managed_cluster.agent_pool_profiles is not None:
            for ap_profile in managed_cluster.agent_pool_profiles:
                for attr in ap_attrs:
                    if getattr(ap_profile, attr, None) is None:
                        delattr(ap_profile, attr)
        for attr in sp_attrs:
            if getattr(managed_cluster.service_principal_profile, attr, None) is None:
                delattr(managed_cluster.service_principal_profile, attr)
    return managed_clusters


def aks_get_credentials(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    name,
    admin=False,
    user="clusterUser",
    path=os.path.join(os.path.expanduser("~"), ".kube", "config"),
    overwrite_existing=False,
    context_name=None,
    public_fqdn=False,
    credential_format=None,
    aks_custom_headers=None,
):
    headers = get_aks_custom_headers(aks_custom_headers)
    credentialResults = None
    serverType = None
    if public_fqdn:
        serverType = 'public'
    if credential_format:
        credential_format = credential_format.lower()
        if admin:
            raise InvalidArgumentValueError("--format can only be specified when requesting clusterUser credential.")
    if admin:
        credentialResults = client.list_cluster_admin_credentials(
            resource_group_name, name, serverType, headers=headers)
    else:
        if user.lower() == 'clusteruser':
            credentialResults = client.list_cluster_user_credentials(
                resource_group_name, name, serverType, credential_format, headers=headers)
        elif user.lower() == 'clustermonitoringuser':
            credentialResults = client.list_cluster_monitoring_user_credentials(
                resource_group_name, name, serverType, headers=headers)
        else:
            raise InvalidArgumentValueError("The value of option --user is invalid.")

    # Check if KUBECONFIG environmental variable is set
    # If path is different than default then that means -f/--file is passed
    # in which case we ignore the KUBECONFIG variable
    # KUBECONFIG can be colon separated. If we find that condition, use the first entry
    if "KUBECONFIG" in os.environ and path == os.path.join(os.path.expanduser('~'), '.kube', 'config'):
        kubeconfig_path = os.environ["KUBECONFIG"].split(os.pathsep)[0]
        if kubeconfig_path:
            logger.info("The default path '%s' is replaced by '%s' defined in KUBECONFIG.", path, kubeconfig_path)
            path = kubeconfig_path
        else:
            logger.warning("Invalid path '%s' defined in KUBECONFIG.", kubeconfig_path)

    if not credentialResults:
        raise CLIError("No Kubernetes credentials found.")
    try:
        kubeconfig = credentialResults.kubeconfigs[0].value.decode(
            encoding='UTF-8')
        print_or_merge_credentials(
            path, kubeconfig, overwrite_existing, context_name)
    except (IndexError, ValueError) as exc:
        raise CLIError("Fail to find kubeconfig file.") from exc


def aks_maintenanceconfiguration_list(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name
):
    return client.list_by_managed_cluster(resource_group_name, cluster_name)


def aks_maintenanceconfiguration_show(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    config_name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, config_name: %s ',
                   resource_group_name, cluster_name, config_name)
    return client.get(resource_group_name, cluster_name, config_name)


def aks_maintenanceconfiguration_delete(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    config_name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, config_name: %s ',
                   resource_group_name, cluster_name, config_name)
    return client.delete(resource_group_name, cluster_name, config_name)


# pylint: disable=unused-argument
def aks_maintenanceconfiguration_add(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    config_name,
    config_file=None,
    weekday=None,
    start_hour=None,
    schedule_type=None,
    interval_days=None,
    interval_weeks=None,
    interval_months=None,
    day_of_week=None,
    day_of_month=None,
    week_index=None,
    duration_hours=None,
    utc_offset=None,
    start_date=None,
    start_time=None
):
    configs = client.list_by_managed_cluster(resource_group_name, cluster_name)
    for config in configs:
        if config.name == config_name:
            raise CLIError(
                f"Maintenance configuration '{config_name}' already exists, please try a different name, "
                "use 'aks maintenanceconfiguration list' to get current list of maitenance configurations"
            )
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    return aks_maintenanceconfiguration_update_internal(cmd, client, raw_parameters)


def aks_maintenanceconfiguration_update(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    config_name,
    config_file=None,
    weekday=None,
    start_hour=None,
    schedule_type=None,
    interval_days=None,
    interval_weeks=None,
    interval_months=None,
    day_of_week=None,
    day_of_month=None,
    week_index=None,
    duration_hours=None,
    utc_offset=None,
    start_date=None,
    start_time=None
):
    configs = client.list_by_managed_cluster(resource_group_name, cluster_name)
    found = False
    for config in configs:
        if config.name == config_name:
            found = True
            break
    if not found:
        raise CLIError(
            f"Maintenance configuration '{config_name}' doesn't exist."
            "use 'aks maintenanceconfiguration list' to get current list of maitenance configurations"
        )
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    return aks_maintenanceconfiguration_update_internal(cmd, client, raw_parameters)


# pylint: disable=too-many-locals, unused-argument
def aks_create(
    cmd,
    client,
    resource_group_name,
    name,
    ssh_key_value,
    location=None,
    kubernetes_version="",
    tags=None,
    dns_name_prefix=None,
    node_osdisk_diskencryptionset_id=None,
    disable_local_accounts=False,
    disable_rbac=None,
    edge_zone=None,
    admin_username="azureuser",
    generate_ssh_keys=False,
    no_ssh_key=False,
    pod_cidr=None,
    service_cidr=None,
    dns_service_ip=None,
    docker_bridge_address=None,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    fqdn_subdomain=None,
    api_server_authorized_ip_ranges=None,
    enable_private_cluster=False,
    private_dns_zone=None,
    disable_public_fqdn=False,
    service_principal=None,
    client_secret=None,
    enable_managed_identity=None,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    windows_admin_username=None,
    windows_admin_password=None,
    enable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    skip_subnet_role_assignment=False,
    node_resource_group=None,
    k8s_support_plan=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    defender_config=None,
    disk_driver_version=None,
    disable_disk_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    bootstrap_artifact_source=CONST_ARTIFACT_SOURCE_DIRECT,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_addons=None,  # pylint: disable=redefined-outer-name
    workspace_resource_id=None,
    enable_msi_auth_for_monitoring=True,
    enable_syslog=False,
    data_collection_settings=None,
    ampls_resource_id=None,
    enable_high_log_scale_mode=False,
    aci_subnet_name=None,
    appgw_name=None,
    appgw_subnet_cidr=None,
    appgw_id=None,
    appgw_subnet_id=None,
    appgw_watch_namespace=None,
    enable_sgxquotehelper=False,
    enable_secret_rotation=False,
    rotation_poll_interval=None,
    enable_app_routing=False,
    app_routing_default_nginx_controller=None,
    # nodepool paramerters
    nodepool_name="nodepool1",
    node_vm_size=None,
    os_sku=None,
    snapshot_id=None,
    vnet_subnet_id=None,
    pod_subnet_id=None,
    pod_ip_allocation_mode=None,
    enable_node_public_ip=False,
    node_public_ip_prefix_id=None,
    enable_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    node_count=3,
    nodepool_tags=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    node_osdisk_type=None,
    node_osdisk_size=0,
    vm_set_type=None,
    zones=None,
    ppg=None,
    max_pods=0,
    enable_encryption_at_host=False,
    enable_ultra_ssd=False,
    enable_fips_image=False,
    kubelet_config=None,
    linux_os_config=None,
    host_group_id=None,
    gpu_instance_profile=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ip_families=None,
    pod_cidrs=None,
    service_cidrs=None,
    load_balancer_managed_outbound_ipv6_count=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    enable_workload_identity=False,
    enable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    cluster_snapshot_id=None,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    dns_zone_resource_id=None,
    dns_zone_resource_ids=None,
    enable_keda=False,
    enable_vpa=False,
    enable_optimized_addon_scaling=False,
    enable_cilium_dataplane=False,
    custom_ca_trust_certificates=None,
    # advanced networking
    enable_acns=None,
    disable_acns=None,
    disable_acns_observability=None,
    disable_acns_security=None,
    acns_advanced_networkpolicies=None,
    acns_transit_encryption_type=None,
    enable_retina_flow_logs=None,
    # nodepool
    crg_id=None,
    message_of_the_day=None,
    workload_runtime=None,
    enable_custom_ca_trust=False,
    nodepool_allowed_host_ports=None,
    nodepool_asg_ids=None,
    node_public_ip_tags=None,
    # safeguards parameters
    safeguards_level=None,
    safeguards_version=None,
    safeguards_excluded_ns=None,
    # azure service mesh
    enable_azure_service_mesh=None,
    revision=None,
    # azure monitor profile - metrics
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    # validation for existing cluster
    existing_mc = None
    try:
        existing_mc = client.get(resource_group_name, name)
    # pylint: disable=broad-except
    except Exception as ex:
        logger.debug("failed to get cluster, error: %s", ex)
    if existing_mc:
        raise ClientRequestError(
            f"The cluster '{name}' under resource group '{resource_group_name}' already exists. "
            "Please use command 'az aks update' to update the existing cluster, "
            "or select a different cluster name to create a new cluster."
        )

    # decorator pattern
    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterCreateDecorator
    aks_create_decorator = AKSPreviewManagedClusterCreateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # construct mc profile
        mc = aks_create_decorator.construct_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None

    # send request to create a real managed cluster
    return aks_create_decorator.create_mc(mc)


# pylint: disable=too-many-locals, unused-argument
def aks_update(
    cmd,
    client,
    resource_group_name,
    name,
    tags=None,
    disable_local_accounts=False,
    enable_local_accounts=False,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    enable_force_upgrade=False,
    disable_force_upgrade=False,
    upgrade_override_until=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    api_server_authorized_ip_ranges=None,
    enable_public_fqdn=False,
    disable_public_fqdn=False,
    enable_managed_identity=False,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    disable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    k8s_support_plan=None,
    windows_admin_password=None,
    enable_ahub=False,
    disable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    detach_acr=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    disable_defender=False,
    defender_config=None,
    enable_disk_driver=False,
    disk_driver_version=None,
    disable_disk_driver=False,
    enable_file_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_blob_driver=None,
    enable_snapshot_controller=False,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    disable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    disable_http_proxy=False,
    enable_http_proxy=False,
    bootstrap_artifact_source=None,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_secret_rotation=False,
    disable_secret_rotation=False,
    rotation_poll_interval=None,
    # nodepool paramerters
    enable_cluster_autoscaler=False,
    disable_cluster_autoscaler=False,
    update_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ssh_key_value=None,
    load_balancer_managed_outbound_ipv6_count=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    ip_families=None,
    pod_cidr=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    disable_pod_identity=False,
    enable_workload_identity=False,
    disable_workload_identity=False,
    enable_image_cleaner=False,
    disable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    disable_image_integrity=False,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    enable_keda=False,
    disable_keda=False,
    enable_private_cluster=False,
    disable_private_cluster=False,
    private_dns_zone=None,
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterUpdateDecorator

    # decorator pattern
    aks_update_decorator = AKSPreviewManagedClusterUpdateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # update mc profile
        mc = aks_update_decorator.update_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None
    # send request to update the real managed cluster
    return aks_update_decorator.update_mc(mc)


# pylint: disable=unused-argument
def aks_show(cmd, client, resource_group_name, name, aks_custom_headers=None):
    headers = get_aks_custom_headers(aks_custom_headers)
    mc = client.get(resource_group_name, name, headers=headers)
    return _remove_nulls([mc])[0]


# pylint: disable=unused-argument
def aks_stop(cmd, client, resource_group_name, name, no_wait=False):
    instance = client.get(resource_group_name, name)
    # print warning when stopping a private cluster
    if check_is_private_link_cluster(instance):
        logger.warning(
            "Your private cluster apiserver IP might get changed when it's stopped and started.\n"
            "Any user provisioned private endpoints linked to this private cluster will need to be deleted and "
            "created again. Any user managed DNS record also needs to be updated with the new IP."
        )
    return sdk_no_wait(no_wait, client.begin_stop, resource_group_name, name)


# pylint: disable=unused-argument
def aks_list(cmd, client, resource_group_name=None):
    if resource_group_name:
        managed_clusters = client.list_by_resource_group(resource_group_name)
    else:
        managed_clusters = client.list()
    return _remove_nulls(list(managed_clusters))


def _remove_nulls(managed_clusters):
    """
    Remove some often-empty fields from a list of ManagedClusters, so the JSON representation
    doesn't contain distracting null fields.

    This works around a quirk of the SDK for python behavior. These fields are not sent
    by the server, but get recreated by the CLI's own "to_dict" serialization.
    """
    attrs = ['tags']
    ap_attrs = ['os_disk_size_gb', 'vnet_subnet_id']
    sp_attrs = ['secret']
    for managed_cluster in managed_clusters:
        for attr in attrs:
            if getattr(managed_cluster, attr, None) is None:
                delattr(managed_cluster, attr)
        if managed_cluster.agent_pool_profiles is not None:
            for ap_profile in managed_cluster.agent_pool_profiles:
                for attr in ap_attrs:
                    if getattr(ap_profile, attr, None) is None:
                        delattr(ap_profile, attr)
        for attr in sp_attrs:
            if getattr(managed_cluster.service_principal_profile, attr, None) is None:
                delattr(managed_cluster.service_principal_profile, attr)
    return managed_clusters


def aks_get_credentials(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    name,
    admin=False,
    user="clusterUser",
    path=os.path.join(os.path.expanduser("~"), ".kube", "config"),
    overwrite_existing=False,
    context_name=None,
    public_fqdn=False,
    credential_format=None,
    aks_custom_headers=None,
):
    headers = get_aks_custom_headers(aks_custom_headers)
    credentialResults = None
    serverType = None
    if public_fqdn:
        serverType = 'public'
    if credential_format:
        credential_format = credential_format.lower()
        if admin:
            raise InvalidArgumentValueError("--format can only be specified when requesting clusterUser credential.")
    if admin:
        credentialResults = client.list_cluster_admin_credentials(
            resource_group_name, name, serverType, headers=headers)
    else:
        if user.lower() == 'clusteruser':
            credentialResults = client.list_cluster_user_credentials(

                resource_group_name, name, serverType, credential_format, headers=headers)
        elif user.lower() == 'clustermonitoringuser':
            credentialResults = client.list_cluster_monitoring_user_credentials(
                resource_group_name, name, serverType, headers=headers)
        else:
            raise InvalidArgumentValueError("The value of option --user is invalid.")

    # Check if KUBECONFIG environmental variable is set
    # If path is different than default then that means -f/--file is passed
    # in which case we ignore the KUBECONFIG variable
    # KUBECONFIG can be colon separated. If we find that condition, use the first entry
    if "KUBECONFIG" in os.environ and path == os.path.join(os.path.expanduser('~'), '.kube', 'config'):
        kubeconfig_path = os.environ["KUBECONFIG"].split(os.pathsep)[0]
        if kubeconfig_path:
            logger.info("The default path '%s' is replaced by '%s' defined in KUBECONFIG.", path, kubeconfig_path)
            path = kubeconfig_path
        else:
            logger.warning("Invalid path '%s' defined in KUBECONFIG.", kubeconfig_path)

    if not credentialResults:
        raise CLIError("No Kubernetes credentials found.")
    try:
        kubeconfig = credentialResults.kubeconfigs[0].value.decode(
            encoding='UTF-8')
        print_or_merge_credentials(
            path, kubeconfig, overwrite_existing, context_name)
    except (IndexError, ValueError) as exc:
        raise CLIError("Fail to find kubeconfig file.") from exc


def aks_maintenanceconfiguration_list(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name
):
    return client.list_by_managed_cluster(resource_group_name, cluster_name)


def aks_maintenanceconfiguration_show(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    config_name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, config_name: %s ',
                   resource_group_name, cluster_name, config_name)
    return client.get(resource_group_name, cluster_name, config_name)


def aks_maintenanceconfiguration_delete(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    config_name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, config_name: %s ',
                   resource_group_name, cluster_name, config_name)
    return client.delete(resource_group_name, cluster_name, config_name)


# pylint: disable=unused-argument
def aks_maintenanceconfiguration_add(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    config_name,
    config_file=None,
    weekday=None,
    start_hour=None,
    schedule_type=None,
    interval_days=None,
    interval_weeks=None,
    interval_months=None,
    day_of_week=None,
    day_of_month=None,
    week_index=None,
    duration_hours=None,
    utc_offset=None,
    start_date=None,
    start_time=None
):
    configs = client.list_by_managed_cluster(resource_group_name, cluster_name)
    for config in configs:
        if config.name == config_name:
            raise CLIError(
                f"Maintenance configuration '{config_name}' already exists, please try a different name, "
                "use 'aks maintenanceconfiguration list' to get current list of maitenance configurations"
            )
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    return aks_maintenanceconfiguration_update_internal(cmd, client, raw_parameters)


def aks_maintenanceconfiguration_update(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    config_name,
    config_file=None,
    weekday=None,
    start_hour=None,
    schedule_type=None,
    interval_days=None,
    interval_weeks=None,
    interval_months=None,
    day_of_week=None,
    day_of_month=None,
    week_index=None,
    duration_hours=None,
    utc_offset=None,
    start_date=None,
    start_time=None
):
    configs = client.list_by_managed_cluster(resource_group_name, cluster_name)
    found = False
    for config in configs:
        if config.name == config_name:
            found = True
            break
    if not found:
        raise CLIError(
            f"Maintenance configuration '{config_name}' doesn't exist."
            "use 'aks maintenanceconfiguration list' to get current list of maitenance configurations"
        )
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    return aks_maintenanceconfiguration_update_internal(cmd, client, raw_parameters)


# pylint: disable=too-many-locals, unused-argument
def aks_create(
    cmd,
    client,
    resource_group_name,
    name,
    ssh_key_value,
    location=None,
    kubernetes_version="",
    tags=None,
    dns_name_prefix=None,
    node_osdisk_diskencryptionset_id=None,
    disable_local_accounts=False,
    disable_rbac=None,
    edge_zone=None,
    admin_username="azureuser",
    generate_ssh_keys=False,
    no_ssh_key=False,
    pod_cidr=None,
    service_cidr=None,
    dns_service_ip=None,
    docker_bridge_address=None,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    fqdn_subdomain=None,
    api_server_authorized_ip_ranges=None,
    enable_private_cluster=False,
    private_dns_zone=None,
    disable_public_fqdn=False,
    service_principal=None,
    client_secret=None,
    enable_managed_identity=None,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    windows_admin_username=None,
    windows_admin_password=None,
    enable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    skip_subnet_role_assignment=False,
    node_resource_group=None,
    k8s_support_plan=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    defender_config=None,
    disk_driver_version=None,
    disable_disk_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    bootstrap_artifact_source=CONST_ARTIFACT_SOURCE_DIRECT,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_addons=None,  # pylint: disable=redefined-outer-name
    workspace_resource_id=None,
    enable_msi_auth_for_monitoring=True,
    enable_syslog=False,
    data_collection_settings=None,
    ampls_resource_id=None,
    enable_high_log_scale_mode=False,
    aci_subnet_name=None,
    appgw_name=None,
    appgw_subnet_cidr=None,
    appgw_id=None,
    appgw_subnet_id=None,
    appgw_watch_namespace=None,
    enable_sgxquotehelper=False,
    enable_secret_rotation=False,
    rotation_poll_interval=None,
    enable_app_routing=False,
    app_routing_default_nginx_controller=None,
    # nodepool paramerters
    nodepool_name="nodepool1",
    node_vm_size=None,
    os_sku=None,
    snapshot_id=None,
    vnet_subnet_id=None,
    pod_subnet_id=None,
    pod_ip_allocation_mode=None,
    enable_node_public_ip=False,
    node_public_ip_prefix_id=None,
    enable_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    node_count=3,
    nodepool_tags=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    node_osdisk_type=None,
    node_osdisk_size=0,
    vm_set_type=None,
    zones=None,
    ppg=None,
    max_pods=0,
    enable_encryption_at_host=False,
    enable_ultra_ssd=False,
    enable_fips_image=False,
    kubelet_config=None,
    linux_os_config=None,
    host_group_id=None,
    gpu_instance_profile=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ip_families=None,
    pod_cidrs=None,
    service_cidrs=None,
    load_balancer_managed_outbound_ipv6_count=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    enable_workload_identity=False,
    enable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    cluster_snapshot_id=None,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    dns_zone_resource_id=None,
    dns_zone_resource_ids=None,
    enable_keda=False,
    enable_vpa=False,
    enable_optimized_addon_scaling=False,
    enable_cilium_dataplane=False,
    custom_ca_trust_certificates=None,
    # advanced networking
    enable_acns=None,
    disable_acns=None,
    disable_acns_observability=None,
    disable_acns_security=None,
    acns_advanced_networkpolicies=None,
    acns_transit_encryption_type=None,
    enable_retina_flow_logs=None,
    # nodepool
    crg_id=None,
    message_of_the_day=None,
    workload_runtime=None,
    enable_custom_ca_trust=False,
    nodepool_allowed_host_ports=None,
    nodepool_asg_ids=None,
    node_public_ip_tags=None,
    # safeguards parameters
    safeguards_level=None,
    safeguards_version=None,
    safeguards_excluded_ns=None,
    # azure service mesh
    enable_azure_service_mesh=None,
    revision=None,
    # azure monitor profile - metrics
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    disable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    # validation for existing cluster
    existing_mc = None
    try:
        existing_mc = client.get(resource_group_name, name)
    # pylint: disable=broad-except
    except Exception as ex:
        logger.debug("failed to get cluster, error: %s", ex)
    if existing_mc:
        raise ClientRequestError(
            f"The cluster '{name}' under resource group '{resource_group_name}' already exists. "
            "Please use command 'az aks update' to update the existing cluster, "
            "or select a different cluster name to create a new cluster."
        )

    # decorator pattern
    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterCreateDecorator
    aks_create_decorator = AKSPreviewManagedClusterCreateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # construct mc profile
        mc = aks_create_decorator.construct_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None

    # send request to create a real managed cluster
    return aks_create_decorator.create_mc(mc)


# pylint: disable=too-many-locals, unused-argument
def aks_update(
    cmd,
    client,
    resource_group_name,
    name,
    tags=None,
    disable_local_accounts=False,
    enable_local_accounts=False,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    enable_force_upgrade=False,
    disable_force_upgrade=False,
    upgrade_override_until=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    api_server_authorized_ip_ranges=None,
    enable_public_fqdn=False,
    disable_public_fqdn=False,
    enable_managed_identity=False,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    disable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    k8s_support_plan=None,
    windows_admin_password=None,
    enable_ahub=False,
    disable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    detach_acr=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    disable_defender=False,
    defender_config=None,
    enable_disk_driver=False,
    disk_driver_version=None,
    disable_disk_driver=False,
    enable_file_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_blob_driver=None,
    enable_snapshot_controller=False,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    disable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    disable_http_proxy=False,
    enable_http_proxy=False,
    bootstrap_artifact_source=None,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_secret_rotation=False,
    disable_secret_rotation=False,
    rotation_poll_interval=None,
    # nodepool paramerters
    enable_cluster_autoscaler=False,
    disable_cluster_autoscaler=False,
    update_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ssh_key_value=None,
    load_balancer_managed_outbound_ipv6_count=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    ip_families=None,
    pod_cidr=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    disable_pod_identity=False,
    enable_workload_identity=False,
    disable_workload_identity=False,
    enable_image_cleaner=False,
    disable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    disable_image_integrity=False,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    enable_keda=False,
    disable_keda=False,
    enable_private_cluster=False,
    disable_private_cluster=False,
    private_dns_zone=None,
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterUpdateDecorator

    # decorator pattern
    aks_update_decorator = AKSPreviewManagedClusterUpdateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # update mc profile
        mc = aks_update_decorator.update_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None
    # send request to update the real managed cluster
    return aks_update_decorator.update_mc(mc)


# pylint: disable=unused-argument
def aks_show(cmd, client, resource_group_name, name, aks_custom_headers=None):
    headers = get_aks_custom_headers(aks_custom_headers)
    mc = client.get(resource_group_name, name, headers=headers)
    return _remove_nulls([mc])[0]


# pylint: disable=unused-argument
def aks_stop(cmd, client, resource_group_name, name, no_wait=False):
    instance = client.get(resource_group_name, name)
    # print warning when stopping a private cluster
    if check_is_private_link_cluster(instance):
        logger.warning(
            "Your private cluster apiserver IP might get changed when it's stopped and started.\n"
            "Any user provisioned private endpoints linked to this private cluster will need to be deleted and "
            "created again. Any user managed DNS record also needs to be updated with the new IP."
        )
    return sdk_no_wait(no_wait, client.begin_stop, resource_group_name, name)


# pylint: disable=unused-argument
def aks_list(cmd, client, resource_group_name=None):
    if resource_group_name:
        managed_clusters = client.list_by_resource_group(resource_group_name)
    else:
        managed_clusters = client.list()
    return _remove_nulls(list(managed_clusters))


def _remove_nulls(managed_clusters):
    """
    Remove some often-empty fields from a list of ManagedClusters, so the JSON representation
    doesn't contain distracting null fields.

    This works around a quirk of the SDK for python behavior. These fields are not sent
    by the server, but get recreated by the CLI's own "to_dict" serialization.
    """
    attrs = ['tags']
    ap_attrs = ['os_disk_size_gb', 'vnet_subnet_id']
    sp_attrs = ['secret']
    for managed_cluster in managed_clusters:
        for attr in attrs:
            if getattr(managed_cluster, attr, None) is None:
                delattr(managed_cluster, attr)
        if managed_cluster.agent_pool_profiles is not None:
            for ap_profile in managed_cluster.agent_pool_profiles:
                for attr in ap_attrs:
                    if getattr(ap_profile, attr, None) is None:
                        delattr(ap_profile, attr)
        for attr in sp_attrs:
            if getattr(managed_cluster.service_principal_profile, attr, None) is None:
                delattr(managed_cluster.service_principal_profile, attr)
    return managed_clusters


def aks_get_credentials(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    name,
    admin=False,
    user="clusterUser",
    path=os.path.join(os.path.expanduser("~"), ".kube", "config"),
    overwrite_existing=False,
    context_name=None,
    public_fqdn=False,
    credential_format=None,
    aks_custom_headers=None,
):
    headers = get_aks_custom_headers(aks_custom_headers)
    credentialResults = None
    serverType = None
    if public_fqdn:
        serverType = 'public'
    if credential_format:
        credential_format = credential_format.lower()
        if admin:
            raise InvalidArgumentValueError("--format can only be specified when requesting clusterUser credential.")
    if admin:
        credentialResults = client.list_cluster_admin_credentials(
            resource_group_name, name, serverType, headers=headers)
    else:
        if user.lower() == 'clusteruser':
            credentialResults = client.list_cluster_user_credentials(
                resource_group_name, name, serverType, credential_format, headers=headers)
        elif user.lower() == 'clustermonitoringuser':
            credentialResults = client.list_cluster_monitoring_user_credentials(
                resource_group_name, name, serverType, headers=headers)
        else:
            raise InvalidArgumentValueError("The value of option --user is invalid.")

    # Check if KUBECONFIG environmental variable is set
    # If path is different than default then that means -f/--file is passed
    # in which case we ignore the KUBECONFIG variable
    # KUBECONFIG can be colon separated. If we find that condition, use the first entry
    if "KUBECONFIG" in os.environ and path == os.path.join(os.path.expanduser('~'), '.kube', 'config'):
        kubeconfig_path = os.environ["KUBECONFIG"].split(os.pathsep)[0]
        if kubeconfig_path:
            logger.info("The default path '%s' is replaced by '%s' defined in KUBECONFIG.", path, kubeconfig_path)
            path = kubeconfig_path
        else:
            logger.warning("Invalid path '%s' defined in KUBECONFIG.", kubeconfig_path)

    if not credentialResults:
        raise CLIError("No Kubernetes credentials found.")
    try:
        kubeconfig = credentialResults.kubeconfigs[0].value.decode(
            encoding='UTF-8')
        print_or_merge_credentials(
            path, kubeconfig, overwrite_existing, context_name)
    except (IndexError, ValueError) as exc:
        raise CLIError("Fail to find kubeconfig file.") from exc


def aks_maintenanceconfiguration_list(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name
):
    return client.list_by_managed_cluster(resource_group_name, cluster_name)


def aks_maintenanceconfiguration_show(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    config_name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, config_name: %s ',
                   resource_group_name, cluster_name, config_name)
    return client.get(resource_group_name, cluster_name, config_name)


def aks_maintenanceconfiguration_delete(
    cmd,  # pylint: disable=unused-argument
    client,
    resource_group_name,
    cluster_name,
    config_name
):
    logger.warning('resource_group_name: %s, cluster_name: %s, config_name: %s ',
                   resource_group_name, cluster_name, config_name)
    return client.delete(resource_group_name, cluster_name, config_name)


# pylint: disable=unused-argument
def aks_maintenanceconfiguration_add(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    config_name,
    config_file=None,
    weekday=None,
    start_hour=None,
    schedule_type=None,
    interval_days=None,
    interval_weeks=None,
    interval_months=None,
    day_of_week=None,
    day_of_month=None,
    week_index=None,
    duration_hours=None,
    utc_offset=None,
    start_date=None,
    start_time=None
):
    configs = client.list_by_managed_cluster(resource_group_name, cluster_name)
    for config in configs:
        if config.name == config_name:
            raise CLIError(
                f"Maintenance configuration '{config_name}' already exists, please try a different name, "
                "use 'aks maintenanceconfiguration list' to get current list of maitenance configurations"
            )
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    return aks_maintenanceconfiguration_update_internal(cmd, client, raw_parameters)


def aks_maintenanceconfiguration_update(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    config_name,
    config_file=None,
    weekday=None,
    start_hour=None,
    schedule_type=None,
    interval_days=None,
    interval_weeks=None,
    interval_months=None,
    day_of_week=None,
    day_of_month=None,
    week_index=None,
    duration_hours=None,
    utc_offset=None,
    start_date=None,
    start_time=None
):
    configs = client.list_by_managed_cluster(resource_group_name, cluster_name)
    found = False
    for config in configs:
        if config.name == config_name:
            found = True
            break
    if not found:
        raise CLIError(
            f"Maintenance configuration '{config_name}' doesn't exist."
            "use 'aks maintenanceconfiguration list' to get current list of maitenance configurations"
        )
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    return aks_maintenanceconfiguration_update_internal(cmd, client, raw_parameters)


# pylint: disable=too-many-locals, unused-argument
def aks_create(
    cmd,
    client,
    resource_group_name,
    name,
    ssh_key_value,
    location=None,
    kubernetes_version="",
    tags=None,
    dns_name_prefix=None,
    node_osdisk_diskencryptionset_id=None,
    disable_local_accounts=False,
    disable_rbac=None,
    edge_zone=None,
    admin_username="azureuser",
    generate_ssh_keys=False,
    no_ssh_key=False,
    pod_cidr=None,
    service_cidr=None,
    dns_service_ip=None,
    docker_bridge_address=None,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    fqdn_subdomain=None,
    api_server_authorized_ip_ranges=None,
    enable_private_cluster=False,
    private_dns_zone=None,
    disable_public_fqdn=False,
    service_principal=None,
    client_secret=None,
    enable_managed_identity=None,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    windows_admin_username=None,
    windows_admin_password=None,
    enable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    skip_subnet_role_assignment=False,
    node_resource_group=None,
    k8s_support_plan=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    defender_config=None,
    disk_driver_version=None,
    disable_disk_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    bootstrap_artifact_source=CONST_ARTIFACT_SOURCE_DIRECT,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_addons=None,  # pylint: disable=redefined-outer-name
    workspace_resource_id=None,
    enable_msi_auth_for_monitoring=True,
    enable_syslog=False,
    data_collection_settings=None,
    ampls_resource_id=None,
    enable_high_log_scale_mode=False,
    aci_subnet_name=None,
    appgw_name=None,
    appgw_subnet_cidr=None,
    appgw_id=None,
    appgw_subnet_id=None,
    appgw_watch_namespace=None,
    enable_sgxquotehelper=False,
    enable_secret_rotation=False,
    rotation_poll_interval=None,
    enable_app_routing=False,
    app_routing_default_nginx_controller=None,
    # nodepool paramerters
    nodepool_name="nodepool1",
    node_vm_size=None,
    os_sku=None,
    snapshot_id=None,
    vnet_subnet_id=None,
    pod_subnet_id=None,
    pod_ip_allocation_mode=None,
    enable_node_public_ip=False,
    node_public_ip_prefix_id=None,
    enable_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    node_count=3,
    nodepool_tags=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    node_osdisk_type=None,
    node_osdisk_size=0,
    vm_set_type=None,
    zones=None,
    ppg=None,
    max_pods=0,
    enable_encryption_at_host=False,
    enable_ultra_ssd=False,
    enable_fips_image=False,
    kubelet_config=None,
    linux_os_config=None,
    host_group_id=None,
    gpu_instance_profile=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ip_families=None,
    pod_cidrs=None,
    service_cidrs=None,
    load_balancer_managed_outbound_ipv6_count=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    enable_workload_identity=False,
    enable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    cluster_snapshot_id=None,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    dns_zone_resource_id=None,
    dns_zone_resource_ids=None,
    enable_keda=False,
    enable_vpa=False,
    enable_optimized_addon_scaling=False,
    enable_cilium_dataplane=False,
    custom_ca_trust_certificates=None,
    # advanced networking
    enable_acns=None,
    disable_acns=None,
    disable_acns_observability=None,
    disable_acns_security=None,
    acns_advanced_networkpolicies=None,
    acns_transit_encryption_type=None,
    enable_retina_flow_logs=None,
    # nodepool
    crg_id=None,
    message_of_the_day=None,
    workload_runtime=None,
    enable_custom_ca_trust=False,
    nodepool_allowed_host_ports=None,
    nodepool_asg_ids=None,
    node_public_ip_tags=None,
    # safeguards parameters
    safeguards_level=None,
    safeguards_version=None,
    safeguards_excluded_ns=None,
    # azure service mesh
    enable_azure_service_mesh=None,
    revision=None,
    # azure monitor profile - metrics
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    disable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    # validation for existing cluster
    existing_mc = None
    try:
        existing_mc = client.get(resource_group_name, name)
    # pylint: disable=broad-except
    except Exception as ex:
        logger.debug("failed to get cluster, error: %s", ex)
    if existing_mc:
        raise ClientRequestError(
            f"The cluster '{name}' under resource group '{resource_group_name}' already exists. "
            "Please use command 'az aks update' to update the existing cluster, "
            "or select a different cluster name to create a new cluster."
        )

    # decorator pattern
    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterCreateDecorator
    aks_create_decorator = AKSPreviewManagedClusterCreateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # construct mc profile
        mc = aks_create_decorator.construct_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None

    # send request to create a real managed cluster
    return aks_create_decorator.create_mc(mc)


# pylint: disable=too-many-locals, unused-argument
def aks_update(
    cmd,
    client,
    resource_group_name,
    name,
    tags=None,
    disable_local_accounts=False,
    enable_local_accounts=False,
    load_balancer_sku=None,
    load_balancer_managed_outbound_ip_count=None,
    load_balancer_outbound_ips=None,
    load_balancer_outbound_ip_prefixes=None,
    load_balancer_outbound_ports=None,
    load_balancer_idle_timeout=None,
    load_balancer_backend_pool_type=None,
    nat_gateway_managed_outbound_ip_count=None,
    nat_gateway_idle_timeout=None,
    kube_proxy_config=None,
    auto_upgrade_channel=None,
    node_os_upgrade_channel=None,
    enable_force_upgrade=False,
    disable_force_upgrade=False,
    upgrade_override_until=None,
    cluster_autoscaler_profile=None,
    sku=None,
    tier=None,
    api_server_authorized_ip_ranges=None,
    enable_public_fqdn=False,
    disable_public_fqdn=False,
    enable_managed_identity=False,
    assign_identity=None,
    assign_kubelet_identity=None,
    enable_aad=False,
    enable_azure_rbac=False,
    disable_azure_rbac=False,
    aad_tenant_id=None,
    aad_admin_group_object_ids=None,
    enable_oidc_issuer=False,
    k8s_support_plan=None,
    windows_admin_password=None,
    enable_ahub=False,
    disable_ahub=False,
    enable_windows_gmsa=False,
    gmsa_dns_server=None,
    gmsa_root_domain_name=None,
    attach_acr=None,
    detach_acr=None,
    nrg_lockdown_restriction_level=None,
    enable_defender=False,
    disable_defender=False,
    defender_config=None,
    enable_disk_driver=False,
    disk_driver_version=None,
    disable_disk_driver=False,
    enable_file_driver=False,
    disable_file_driver=False,
    enable_blob_driver=None,
    disable_blob_driver=None,
    enable_snapshot_controller=False,
    disable_snapshot_controller=False,
    enable_azure_keyvault_kms=False,
    disable_azure_keyvault_kms=False,
    azure_keyvault_kms_key_id=None,
    azure_keyvault_kms_key_vault_network_access=None,
    azure_keyvault_kms_key_vault_resource_id=None,
    http_proxy_config=None,
    disable_http_proxy=False,
    enable_http_proxy=False,
    bootstrap_artifact_source=None,
    bootstrap_container_registry_resource_id=None,
    # addons
    enable_secret_rotation=False,
    disable_secret_rotation=False,
    rotation_poll_interval=None,
    # nodepool paramerters
    enable_cluster_autoscaler=False,
    disable_cluster_autoscaler=False,
    update_cluster_autoscaler=False,
    min_count=None,
    max_count=None,
    nodepool_labels=None,
    nodepool_taints=None,
    nodepool_initialization_taints=None,
    # misc
    yes=False,
    no_wait=False,
    aks_custom_headers=None,
    # extensions
    # managed cluster
    ssh_key_value=None,
    load_balancer_managed_outbound_ipv6_count=None,
    outbound_type=None,
    network_plugin=None,
    network_plugin_mode=None,
    network_policy=None,
    network_dataplane=None,
    ip_families=None,
    pod_cidr=None,
    enable_pod_identity=False,
    enable_pod_identity_with_kubenet=False,
    disable_pod_identity=False,
    enable_workload_identity=False,
    disable_workload_identity=False,
    enable_image_cleaner=False,
    disable_image_cleaner=False,
    image_cleaner_interval_hours=None,
    enable_image_integrity=False,
    disable_image_integrity=False,
    enable_apiserver_vnet_integration=False,
    apiserver_subnet_id=None,
    enable_keda=False,
    disable_keda=False,
    enable_private_cluster=False,
    disable_private_cluster=False,
    private_dns_zone=None,
    enable_azuremonitormetrics=False,
    enable_azure_monitor_metrics=False,
    azure_monitor_workspace_resource_id=None,
    ksm_metric_labels_allow_list=None,
    ksm_metric_annotations_allow_list=None,
    grafana_resource_id=None,
    enable_windows_recording_rules=False,
    # azure monitor profile - app monitoring
    enable_azure_monitor_app_monitoring=False,
    # metrics profile
    enable_cost_analysis=False,
    # AI toolchain operator
    enable_ai_toolchain_operator=False,
    # azure container storage
    enable_azure_container_storage=None,
    disable_azure_container_storage=None,
    storage_pool_name=None,
    storage_pool_size=None,
    storage_pool_sku=None,
    storage_pool_option=None,
    ephemeral_disk_volume_type=None,
    ephemeral_disk_nvme_perf_tier=None,
    node_provisioning_mode=None,
    node_provisioning_default_pools=None,
    # trusted launch
    enable_secure_boot=False,
    enable_vtpm=False,
    cluster_service_load_balancer_health_probe_mode=None,
    if_match=None,
    if_none_match=None,
    # Static Egress Gateway
    enable_static_egress_gateway=False,
    # virtualmachines
    vm_sizes=None,
    # IMDS restriction
    enable_imds_restriction=False,
):
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()

    from azure.cli.command_modules.acs._consts import DecoratorEarlyExitException
    from azext_aks_preview.managed_cluster_decorator import AKSPreviewManagedClusterUpdateDecorator

    # decorator pattern
    aks_update_decorator = AKSPreviewManagedClusterUpdateDecorator(
        cmd=cmd,
        client=client,
        raw_parameters=raw_parameters,
        resource_type=CUSTOM_MGMT_AKS_PREVIEW,
    )
    try:
        # update mc profile
        mc = aks_update_decorator.update_mc_profile_preview()
    except DecoratorEarlyExitException:
        # exit gracefully
        return None
    # send request to update the real managed cluster
    return aks_update_decorator.update_mc(mc)


# HolmesGPT Debug Commands

def aks_debug_ask(
    cmd,  # pylint: disable=unused-argument
    client=None,  # pylint: disable=unused-argument
    resource_group_name=None,
    cluster_name=None,
    question=None,
    context=None,
    context_namespace=None,
    context_labels=None,
    context_since=None,
    context_hours=None,
    context_type=None,
    context_filter=None,
    context_include_events=False,
    context_include_logs=False,
    context_include_monitoring=False,
    context_include_traces=False,
    history=None,
    model=None,
    max_tokens=None,
    temperature=None,
    top_p=None,    backend=None,
    engine=None,
    lang=None,
    output_format=None,
    no_cache=False,
    refresh_cache=False,
    config=None,
    verbose=False,
    explain=False,
):
    """
    Wrapper function for HolmesGPT ask command to debug AKS clusters.
    """
    import subprocess
    import json
    
    # Build the holmes command
    cmd_args = ["holmes", "ask", question]
    
    # Add context flags
    if context:
        cmd_args.extend(["--context", context])
    if context_namespace:
        cmd_args.extend(["--context-namespace", context_namespace])
    if context_labels:
        cmd_args.extend(["--context-labels", context_labels])
    if context_since:
        cmd_args.extend(["--context-since", context_since])
    if context_hours:
        cmd_args.extend(["--context-hours", str(context_hours)])
    if context_type:
        cmd_args.extend(["--context-type", context_type])
    if context_filter:
        cmd_args.extend(["--context-filter", context_filter])
    if context_include_events:
        cmd_args.append("--context-include-events")
    if context_include_logs:
        cmd_args.append("--context-include-logs")
    if context_include_monitoring:
        cmd_args.append("--context-include-monitoring")
    if context_include_traces:
        cmd_args.append("--context-include-traces")
    
    # Add model configuration flags
    if history:
        cmd_args.extend(["--history", history])
    if model:
        cmd_args.extend(["--model", model])
    if max_tokens:
        cmd_args.extend(["--max-tokens", str(max_tokens)])
    if temperature:
        cmd_args.extend(["--temperature", str(temperature)])
    if top_p:
        cmd_args.extend(["--top-p", str(top_p)])
    if backend:
        cmd_args.extend(["--backend", backend])
    if engine:
        cmd_args.extend(["--engine", engine])
    if lang:
        cmd_args.extend(["--lang", lang])
    
    # Add output and behavior flags    if output_format:
        cmd_args.extend(["--output", output_format])
    if no_cache:
        cmd_args.append("--no-cache")
    if refresh_cache:
        cmd_args.append("--refresh-cache")
    if config:
        cmd_args.extend(["--config", config])
    if verbose:
        cmd_args.append("--verbose")
    if explain:
        cmd_args.append("--explain")
    
    try:        # Execute the holmes command
        logger.info("Executing HolmesGPT ask command for cluster %s in resource group %s", 
                   cluster_name, resource_group_name)
        result = subprocess.run(cmd_args, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True)
        
        # Return the output
        if output_format == "json":
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"output": result.stdout, "stderr": result.stderr}
        else:
            print(result.stdout)
            if result.stderr:
                print("Warnings/Errors:", result.stderr)
            return {"output": result.stdout, "stderr": result.stderr}
            
    except subprocess.CalledProcessError as e:
        error_msg = f"HolmesGPT command failed with exit code {e.returncode}: {e.stderr}"
        logger.error(error_msg)
        raise CLIError(error_msg)
    except FileNotFoundError:
        error_msg = ("HolmesGPT CLI not found. Please ensure HolmesGPT is installed and available in your PATH. "
                    "Install it with: pip install holmesgpt")
        logger.error(error_msg)
        raise CLIError(error_msg)


def aks_debug_investigate(
    cmd,  # pylint: disable=unused-argument
    client=None,  # pylint: disable=unused-argument
    resource_group_name=None,
    cluster_name=None,
    context=None,
    context_namespace=None,
    context_labels=None,
    context_since=None,
    context_hours=None,
    context_type=None,
    context_filter=None,
    context_include_events=False,
    context_include_logs=False,
    context_include_monitoring=False,
    context_include_traces=False,
    history=None,
    model=None,
    max_tokens=None,
    temperature=None,
    top_p=None,    backend=None,
    engine=None,
    lang=None,
    output_format=None,
    no_cache=False,
    refresh_cache=False,
    config=None,
    verbose=False,
    explain=False,
):
    """
    Wrapper function for HolmesGPT investigate command to debug AKS clusters.
    """
    import subprocess
    import json
    
    # Build the holmes command
    cmd_args = ["holmes", "investigate"]
    
    # Add context flags
    if context:
        cmd_args.extend(["--context", context])
    if context_namespace:
        cmd_args.extend(["--context-namespace", context_namespace])
    if context_labels:
        cmd_args.extend(["--context-labels", context_labels])
    if context_since:
        cmd_args.extend(["--context-since", context_since])
    if context_hours:
        cmd_args.extend(["--context-hours", str(context_hours)])
    if context_type:
        cmd_args.extend(["--context-type", context_type])
    if context_filter:
        cmd_args.extend(["--context-filter", context_filter])
    if context_include_events:
        cmd_args.append("--context-include-events")
    if context_include_logs:
        cmd_args.append("--context-include-logs")
    if context_include_monitoring:
        cmd_args.append("--context-include-monitoring")
    if context_include_traces:
        cmd_args.append("--context-include-traces")
    
    # Add model configuration flags
    if history:
        cmd_args.extend(["--history", history])
    if model:
        cmd_args.extend(["--model", model])
    if max_tokens:
        cmd_args.extend(["--max-tokens", str(max_tokens)])
    if temperature:
        cmd_args.extend(["--temperature", str(temperature)])
    if top_p:
        cmd_args.extend(["--top-p", str(top_p)])
    if backend:
        cmd_args.extend(["--backend", backend])
    if engine:
        cmd_args.extend(["--engine", engine])
    if lang:
        cmd_args.extend(["--lang", lang])
    
    # Add output and behavior flags
    if output_format:
        cmd_args.extend(["--output", output_format])
    if no_cache:
        cmd_args.append("--no-cache")
    if refresh_cache:
        cmd_args.append("--refresh-cache")
    if config:
        cmd_args.extend(["--config", config])
    if verbose:
        cmd_args.append("--verbose")
    if explain:
        cmd_args.append("--explain")
    
    try:        # Execute the holmes command
        logger.info("Executing HolmesGPT investigate command for cluster %s in resource group %s", 
                   cluster_name, resource_group_name)
        result = subprocess.run(cmd_args, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True)
        
        # Return the output
        if output_format == "json":
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"output": result.stdout, "stderr": result.stderr}
        else:
            print(result.stdout)
            if result.stderr:
                print("Warnings/Errors:", result.stderr)
            return {"output": result.stdout, "stderr": result.stderr}
            
    except subprocess.CalledProcessError as e:
        error_msg = f"HolmesGPT command failed with exit code {e.returncode}: {e.stderr}"
        logger.error(error_msg)
        raise CLIError(error_msg)
    except FileNotFoundError:
        error_msg = ("HolmesGPT CLI not found. Please ensure HolmesGPT is installed and available in your PATH. "
                    "Install it with: pip install holmesgpt")
        logger.error(error_msg)
        raise CLIError(error_msg)



def create_k8s_extension(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    name,
    extension_type,
    scope=None,
    target_namespace=None,
    release_namespace=None,
    configuration_settings=None,
    configuration_protected_settings=None,
    configuration_settings_file=None,
    configuration_protected_settings_file=None,
    no_wait=False,
):
    raise_validation_error_if_extension_type_not_in_allow_list(extension_type.lower())
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_operation(cmd.cli_ctx)

    try:
        result = k8s_extension_custom_mod.create_k8s_extension(
            cmd,
            client,
            resource_group_name,
            cluster_name,
            name=name,
            cluster_type="managedClusters",
            extension_type=extension_type,
            scope=scope,
            target_namespace=target_namespace,
            release_namespace=release_namespace,
            configuration_settings=configuration_settings,
            configuration_protected_settings=configuration_protected_settings,
            configuration_settings_file=configuration_settings_file,
            configuration_protected_settings_file=configuration_protected_settings_file,
            no_wait=no_wait,
        )
        return result
    except Exception as ex:
        logger.error("K8s extension failed to install.\nError: %s", ex)


def list_k8s_extension(
    cmd,
    client,
    resource_group_name,
    cluster_name
):
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_operation(cmd.cli_ctx)

    try:
        result = k8s_extension_custom_mod.list_k8s_extension(
            client,
            resource_group_name,
            cluster_name,
            cluster_type="managedClusters",
        )
        return get_all_extensions_in_allow_list(result)
    except Exception as ex:
        logger.error("Failed to list the K8s extension.\nError: %s", ex)


def update_k8s_extension(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    name,
    configuration_settings=None,
    configuration_protected_settings=None,
    configuration_settings_file=None,
    configuration_protected_settings_file=None,
    no_wait=False,
    yes=False,
):
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_operation(cmd.cli_ctx)

    try:
        result = k8s_extension_custom_mod.update_k8s_extension(
            cmd,
            client,
            resource_group_name,
            cluster_name,
            name,
            "managedClusters",
            configuration_settings=configuration_settings,
            configuration_protected_settings=configuration_protected_settings,
            configuration_settings_file=configuration_settings_file,
            configuration_protected_settings_file=configuration_protected_settings_file,
            no_wait=no_wait,
            yes=yes,
        )
        return result
    except Exception as ex:
        logger.error("K8s extension failed to patch.\nError: %s", ex)


def delete_k8s_extension(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    name,
    no_wait=False,
    yes=False,
    force=False,
):
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_operation(cmd.cli_ctx)

    try:
        result = k8s_extension_custom_mod.delete_k8s_extension(
            cmd,
            client,
            resource_group_name,
            cluster_name,
            name,
            "managedClusters",
            no_wait=no_wait,
            yes=yes,
            force=force,
        )
        return result
    except Exception as ex:
        logger.error("Failed to delete K8s extension.\nError: %s", ex)


def show_k8s_extension(cmd, client, resource_group_name, cluster_name, name):
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_operation(cmd.cli_ctx)

    try:
        result = k8s_extension_custom_mod.show_k8s_extension(
            client,
            resource_group_name,
            cluster_name,
            name,
            "managedClusters",
        )
        return get_extension_in_allow_list(result)
    except Exception as ex:
        logger.error("Failed to get K8s extension.\nError: %s", ex)


def list_k8s_extension_types(
    cmd,
    client,
    location=None,
    resource_group_name=None,
    cluster_name=None,
    release_train=None
):
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_types(cmd.cli_ctx)
    try:
        if location:
            result = k8s_extension_custom_mod.list_extension_types_by_location(
                client,
                location,
                cluster_type="managedClusters",
            )
            return get_all_extension_types_in_allow_list(result)
        if cluster_name and resource_group_name:
            result = k8s_extension_custom_mod.list_extension_types_by_cluster(
                client,
                resource_group_name,
                cluster_name,
                "managedClusters",
                release_train=release_train,
            )
            return get_all_extension_types_in_allow_list(result)
    except Exception as ex:
        logger.error("Failed to list K8s extension types by location.\nError: %s", ex)


# get K8s extension type
def show_k8s_extension_type(
    cmd,
    client,
    extension_type,
    location=None,
    resource_group_name=None,
    cluster_name=None
):
    raise_validation_error_if_extension_type_not_in_allow_list(extension_type.lower())
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_types(cmd.cli_ctx)
    try:
        if location:
            result = k8s_extension_custom_mod.show_extension_type_by_location(
                client,
                location,
                extension_type=extension_type,
            )
            return result
        if cluster_name and resource_group_name:
            result = k8s_extension_custom_mod.show_extension_type_by_cluster(
                client,
                resource_group_name,
                cluster_name,
                "managedClusters",
                extension_type,
            )
            return result
    except Exception as ex:
        logger.error("Failed to get K8s extension types by location.\nError: %s", ex)


# list version by location
def list_k8s_extension_type_versions(
    cmd,
    client,
    extension_type,
    location=None,
    resource_group_name=None,
    cluster_name=None,
    release_train=None,
    major_version=None,
    show_latest=False
):
    raise_validation_error_if_extension_type_not_in_allow_list(extension_type.lower())
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_types(cmd.cli_ctx)
    try:
        if location:
            result = k8s_extension_custom_mod.list_extension_type_versions_by_location(
                client,
                location,
                extension_type,
                release_train=release_train,
                cluster_type="managedClusters",
                major_version=major_version,
                show_latest=show_latest,
            )
            return result
        if cluster_name and resource_group_name:
            result = k8s_extension_custom_mod.list_extension_type_versions_by_cluster(
                client,
                resource_group_name,
                "managedClusters",
                cluster_name,
                extension_type,
                release_train=release_train,
                major_version=major_version,
                show_latest=show_latest,
            )
            return result
    except Exception as ex:
        logger.error("Failed to list K8s extension type versions by location.\nError: %s", ex)


# show extension type version
def show_k8s_extension_type_version(
    cmd,
    client,
    extension_type,
    version,
    location=None,
    resource_group_name=None,
    cluster_name=None
):
    raise_validation_error_if_extension_type_not_in_allow_list(extension_type.lower())
    k8s_extension_custom_mod = get_k8s_extension_module(CONST_K8S_EXTENSION_CUSTOM_MOD_NAME)
    client_factory = get_k8s_extension_module(CONST_K8S_EXTENSION_CLIENT_FACTORY_MOD_NAME)
    client = client_factory.cf_k8s_extension_types(cmd.cli_ctx)
    try:
        if location:
            result = k8s_extension_custom_mod.show_extension_type_version_by_location(
                client,
                location,
                extension_type,
                version,
            )
            return result
        if cluster_name and resource_group_name:
            result = k8s_extension_custom_mod.show_extension_type_version_by_cluster(
                client,
                resource_group_name,
                "managedClusters",
                cluster_name,
                extension_type,
                version
            )
            return result
    except Exception as ex:
        logger.error("Failed to get K8s extension type versions by cluster.\nError: %s", ex)


# pylint: disable=unused-argument
def aks_loadbalancer_add(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    name,
    primary_agent_pool_name,
    allow_service_placement=None,
    service_label_selector=None,
    service_namespace_selector=None,
    node_selector=None,
    aks_custom_headers=None,
):
    """Add a load balancer configuration to a managed cluster.
    :param resource_group_name: Name of resource group.
    :type resource_group_name: str
    :param cluster_name: Name of the managed cluster.
    :type cluster_name: str
    :param name: Name of the public load balancer.
    :type name: str
    :param primary_agent_pool_name: Name of the primary agent pool for this load balancer.
    :type primary_agent_pool_name: str
    :param allow_service_placement: Whether to automatically place services on the load balancer. Default is true.
    :type allow_service_placement: bool
    :param service_label_selector: Only services that match this selector can be placed on this load balancer.
    :type service_label_selector: str
    :param service_namespace_selector: Services created in namespaces that match the selector can be
        placed on this load balancer.
    :type service_namespace_selector: str
    :param node_selector: Nodes that match this selector will be possible members of this load balancer.
    :type node_selector: str
    """
    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    from azext_aks_preview.loadbalancerconfiguration import (
        aks_loadbalancer_add_internal,
    )

    return aks_loadbalancer_add_internal(cmd, client, raw_parameters)


def aks_loadbalancer_update(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    name,
    primary_agent_pool_name=None,
    allow_service_placement=None,
    service_label_selector=None,
    service_namespace_selector=None,
    node_selector=None,
    aks_custom_headers=None,
):
    """Update a load balancer configuration in a managed cluster.
    :param resource_group_name: Name of resource group.
    :type resource_group_name: str
    :param cluster_name: Name of the managed cluster.
    :type cluster_name: str
    :param loadbalancer_name: Name of the load balancer configuration.
    :type loadbalancer_name: str
    :param name: Name of the public load balancer.
    :type name: str
    :param primary_agent_pool_name: Name of the primary agent pool for this load balancer.
    :type primary_agent_pool_name: str
    :param allow_service_placement: Whether to automatically place services on the load balancer. Default is true.
    :type allow_service_placement: bool
    :param service_label_selector: Only services that match this selector can be placed on this load balancer.
    :type service_label_selector: str
    :param service_namespace_selector: Services created in namespaces that match the selector can be
        placed on this load balancer.
    :type service_namespace_selector: str
    :param node_selector: Nodes that match this selector will be possible members of this load balancer.
    :type node_selector: str
    """

    # DO NOT MOVE: get all the original parameters and save them as a dictionary
    raw_parameters = locals()
    from azext_aks_preview.loadbalancerconfiguration import (
        aks_loadbalancer_update_internal,
    )

    return aks_loadbalancer_update_internal(cmd, client, raw_parameters)


def aks_loadbalancer_delete(cmd, client, resource_group_name, cluster_name, name):
    """Delete a load balancer configuration in a managed cluster.
    :param resource_group_name: Name of resource group.
    :type resource_group_name: str
    :param cluster_name: Name of the managed cluster.
    :type cluster_name: str
    :param name: Name of the load balancer configuration.
    :type name: str
    """
    return client.begin_delete(resource_group_name, cluster_name, name)


def aks_loadbalancer_list(cmd, client, resource_group_name, cluster_name):
    """List load balancer configurations in a managed cluster.
    :param resource_group_name: Name of resource group.
    :type resource_group_name: str
    :param cluster_name: Name of the managed cluster.
    :type cluster_name: str
    """
    return client.list_by_managed_cluster(resource_group_name, cluster_name)


def aks_loadbalancer_show(cmd, client, resource_group_name, cluster_name, name):
    """Show the details for a load balancer configuration.
    :param resource_group_name: Name of resource group.
    :type resource_group_name: str
    :param cluster_name: Name of the managed cluster.
    :type cluster_name: str
    :param name: Name of the load balancer configuration.
    :type name: str
    """
    return client.get(resource_group_name, cluster_name, name)


# pylint: disable=unused-argument
def aks_loadbalancer_rebalance_nodes(
    cmd,
    client,
    resource_group_name,
    cluster_name,
    load_balancer_names=None,
):
    """Rebalance nodes across specific load balancers.
    :param cmd: Command context
    :param client: AKS client
    :param resource_group_name: Name of resource group.
    :type resource_group_name: str
    :param cluster_name: Name of the managed cluster.
    :type cluster_name: str
    :param load_balancer_names: Names of load balancers to rebalance.
        If not specified, all load balancers will be rebalanced.
    :type load_balancer_names: list[str]
    :param no_wait: Do not wait for the long-running operation to finish.
    :type no_wait: bool
    :return: The result of the rebalance operation
    """
    from azext_aks_preview.loadbalancerconfiguration import (
        aks_loadbalancer_rebalance_internal,
    )
    from azext_aks_preview._client_factory import cf_managed_clusters

    # Get the load balancers client
    managed_clusters_client = cf_managed_clusters(cmd.cli_ctx)

    # Prepare parameters for the internal function
    parameters = {
        "resource_group_name": resource_group_name,
        "cluster_name": cluster_name,
        "load_balancer_names": load_balancer_names,
    }

    return aks_loadbalancer_rebalance_internal(managed_clusters_client, parameters)
