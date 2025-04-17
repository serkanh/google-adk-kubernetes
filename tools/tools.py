from kubernetes import client, config
from kubernetes.client.rest import ApiException
from typing import Dict, List, Optional, Union
from datetime import datetime

config.load_config()


api_v1 = client.CoreV1Api()
apps_v1 = client.AppsV1Api()
batch_v1 = client.BatchV1Api()


def list_namespaces() -> list:
    """
    List all namespaces in the Kubernetes cluster.

    Returns:
        list: A list of namespace names.
    """
    namespaces = api_v1.list_namespace()
    return [ns.metadata.name for ns in namespaces.items]

def list_deployments_from_namespace(namespace: str = "default") -> list:
    """
    List all deployments in a specific namespace.

    Args:
        namespace (str): The namespace to list deployments from. Defaults to "default".

    Returns:
        list: A list of deployment names in the specified namespace.
    """
    deployments = apps_v1.list_namespaced_deployment(namespace)
    return [deploy.metadata.name for deploy in deployments.items]

def list_pods_from_namespace(namespace: str = "default") -> list:
    """
    List all pods in a specific namespace.

    Args:
        namespace (str): The namespace to list pods from. Defaults to "default".

    Returns:
        list: A list of pod names in the specified namespace.
    """
    pods = api_v1.list_namespaced_pod(namespace)
    return [pod.metadata.name for pod in pods.items]

def list_services_from_namespace(namespace: str = "default") -> list:
    """
    List all services in a specific namespace.

    Args:
        namespace (str): The namespace to list services from. Defaults to "default".

    Returns:
        list: A list of service names in the specified namespace.
    """
    services = api_v1.list_namespaced_service(namespace)
    return [svc.metadata.name for svc in services.items]

def list_secrets_from_namespace(namespace: str = "default") -> list:
    """
    List all secrets in a specific namespace.

    Args:
        namespace (str): The namespace to list secrets from. Defaults to "default".

    Returns:
        list: A list of secret names in the specified namespace.
    """
    secrets = api_v1.list_namespaced_secret(namespace)
    return [secret.metadata.name for secret in secrets.items]

def list_daemonsets_from_namespace(namespace: str = "default") -> list:
    """
    List all daemonsets in a specific namespace.

    Args:
        namespace (str): The namespace to list daemonsets from. Defaults to "default".

    Returns:
        list: A list of daemonset names in the specified namespace.
    """
    daemonsets = apps_v1.list_namespaced_daemon_set(namespace)
    return [ds.metadata.name for ds in daemonsets.items]

def list_configmaps_from_namespace(namespace: str = "default") -> list:
    """
    List all configmaps in a specific namespace.

    Args:
        namespace (str): The namespace to list configmaps from. Defaults to "default".

    Returns:
        list: A list of configmap names in the specified namespace.
    """
    configmaps = api_v1.list_namespaced_config_map(namespace)
    return [cm.metadata.name for cm in configmaps.items]

def list_all_resources(namespace: str = "default") -> dict:
    """
    List all resources in a specific namespace.

    Args:
        namespace (str): The namespace to list resources from. Defaults to "default".

    Returns:
        dict: A dictionary containing lists of deployments, pods, services, secrets, daemonsets, and configmaps for a specific namespace.
    """
    resources = {
        "deployments": list_deployments_from_namespace(namespace),
        "pods": list_pods_from_namespace(namespace),
        "services": list_services_from_namespace(namespace),
        "secrets": list_secrets_from_namespace(namespace),
        "daemonsets": list_daemonsets_from_namespace(namespace),
        "configmaps": list_configmaps_from_namespace(namespace)
    }
    return resources

# ... existing code ...

__all__ = [
    "list_namespaces",
    "list_deployments_from_namespace",
    "list_pods_from_namespace",
    "list_services_from_namespace",
    "list_secrets_from_namespace",  # Added
    "list_daemonsets_from_namespace", # Added
    "list_configmaps_from_namespace", # Added
    "list_all_resources",
    "get_deployment_details",
    "get_pod_details",
    "scale_deployment",
    "get_pod_logs",
    "get_resource_health",
    "get_events"
]
