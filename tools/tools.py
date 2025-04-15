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

def list_deployments_from_namespace(namespace: str) -> list:
    """
    List all deployments in a specific namespace.

    Args:
        namespace (str): The namespace to list deployments from.

    Returns:
        list: A list of deployment names in the specified namespace.
    """
    deployments = apps_v1.list_namespaced_deployment(namespace)
    return [deploy.metadata.name for deploy in deployments.items]

def list_pods_from_namespace(namespace: str) -> list:
    """
    List all pods in a specific namespace.

    Args:
        namespace (str): The namespace to list pods from.

    Returns:
        list: A list of pod names in the specified namespace.
    """
    pods = api_v1.list_namespaced_pod(namespace)
    return [pod.metadata.name for pod in pods.items]

def list_services_from_namespace(namespace: str) -> list:
    """
    List all services in a specific namespace.

    Args:
        namespace (str): The namespace to list services from.

    Returns:
        list: A list of service names in the specified namespace.
    """
    services = api_v1.list_namespaced_service(namespace)
    return [svc.metadata.name for svc in services.items]

def list_all_resources(namespace: str) -> dict:
    """
    List all resources in a specific namespace.

    Args:
        namespace (str): The namespace to list resources from.

    Returns:
        dict: A dictionary containing lists of deployments, pods, and services for a specific namespace.
    """
    resources = {
        "deployments": list_deployments_from_namespace(namespace),
        "pods": list_pods_from_namespace(namespace),
        "services": list_services_from_namespace(namespace)
    }
    return resources

def get_deployment_details(namespace: str, deployment_name: str) -> Dict:
    """
    Get detailed information about a specific deployment.

    Args:
        namespace (str): The namespace of the deployment.
        deployment_name (str): The name of the deployment.

    Returns:
        Dict: Detailed information about the deployment.
    """
    try:
        deployment = apps_v1.read_namespaced_deployment(deployment_name, namespace)
        return {
            "name": deployment.metadata.name,
            "namespace": deployment.metadata.namespace,
            "replicas": deployment.spec.replicas,
            "available_replicas": deployment.status.available_replicas,
            "strategy": deployment.spec.strategy.type,
            "containers": [container.name for container in deployment.spec.template.spec.containers]
        }
    except ApiException as e:
        return {"error": f"Failed to get deployment details: {str(e)}"}

def get_pod_details(namespace: str, pod_name: str) -> Dict:
    """
    Get detailed information about a specific pod.

    Args:
        namespace (str): The namespace of the pod.
        pod_name (str): The name of the pod.

    Returns:
        Dict: Detailed information about the pod.
    """
    try:
        pod = api_v1.read_namespaced_pod(pod_name, namespace)
        return {
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "status": pod.status.phase,
            "node": pod.spec.node_name,
            "containers": [container.name for container in pod.spec.containers],
            "start_time": pod.status.start_time,
            "ip": pod.status.pod_ip
        }
    except ApiException as e:
        return {"error": f"Failed to get pod details: {str(e)}"}

def scale_deployment(namespace: str, deployment_name: str, replicas: int) -> Dict:
    """
    Scale a deployment to a specific number of replicas.

    Args:
        namespace (str): The namespace of the deployment.
        deployment_name (str): The name of the deployment.
        replicas (int): The desired number of replicas.

    Returns:
        Dict: Status of the scaling operation.
    """
    try:
        body = {"spec": {"replicas": replicas}}
        apps_v1.patch_namespaced_deployment_scale(deployment_name, namespace, body)
        return {"status": "success", "message": f"Scaled deployment {deployment_name} to {replicas} replicas"}
    except ApiException as e:
        return {"status": "error", "message": f"Failed to scale deployment: {str(e)}"}

def get_pod_logs(namespace: str, pod_name: str, container: Optional[str] = None, tail_lines: int = 100) -> str:
    """
    Get logs from a specific pod.

    Args:
        namespace (str): The namespace of the pod.
        pod_name (str): The name of the pod.
        container (str, optional): The name of the container to get logs from.
        tail_lines (int): Number of lines to return from the end of the logs.

    Returns:
        str: The pod logs.
    """
    try:
        return api_v1.read_namespaced_pod_log(
            pod_name,
            namespace,
            container=container,
            tail_lines=tail_lines
        )
    except ApiException as e:
        return f"Failed to get pod logs: {str(e)}"

def get_resource_health(namespace: str, resource_type: str, resource_name: str) -> Dict:
    """
    Get health status of a specific resource.

    Args:
        namespace (str): The namespace of the resource.
        resource_type (str): Type of resource (pod, deployment, service).
        resource_name (str): Name of the resource.

    Returns:
        Dict: Health status of the resource.
    """
    try:
        if resource_type == "pod":
            pod = api_v1.read_namespaced_pod(resource_name, namespace)
            return {
                "status": pod.status.phase,
                "ready": all(condition.status == "True" for condition in pod.status.conditions),
                "restart_count": sum(container.restart_count for container in pod.status.container_statuses)
            }
        elif resource_type == "deployment":
            deployment = apps_v1.read_namespaced_deployment(resource_name, namespace)
            return {
                "status": "Healthy" if deployment.status.available_replicas == deployment.spec.replicas else "Unhealthy",
                "available_replicas": deployment.status.available_replicas,
                "desired_replicas": deployment.spec.replicas
            }
        else:
            return {"error": f"Unsupported resource type: {resource_type}"}
    except ApiException as e:
        return {"error": f"Failed to get resource health: {str(e)}"}

def get_events(namespace: str = None, limit: int = 200) -> List[Dict]:
    """
    Get Kubernetes events with a configurable limit.

    Args:
        namespace (str, optional): The namespace to get events from. If None, gets events from all namespaces.
        limit (int): Maximum number of events to return. Default is 200.

    Returns:
        List[Dict]: List of events with their details.
    """
    try:
        if namespace:
            events = api_v1.list_namespaced_event(namespace, limit=limit)
        else:
            events = api_v1.list_event_for_all_namespaces(limit=limit)

        formatted_events = []
        for event in events.items:
            formatted_events.append({
                "name": event.metadata.name,
                "namespace": event.metadata.namespace,
                "type": event.type,
                "reason": event.reason,
                "message": event.message,
                "source": {
                    "component": event.source.component if event.source else None,
                    "host": event.source.host if event.source else None
                },
                "first_seen": event.first_timestamp.isoformat() if event.first_timestamp else None,
                "last_seen": event.last_timestamp.isoformat() if event.last_timestamp else None,
                "count": event.count,
                "involved_object": {
                    "kind": event.involved_object.kind,
                    "name": event.involved_object.name,
                    "namespace": event.involved_object.namespace
                } if event.involved_object else None
            })
        return formatted_events
    except ApiException as e:
        return [{"error": f"Failed to get events: {str(e)}"}]

__all__ = [
    "list_namespaces",
    "list_deployments_from_namespace",
    "list_pods_from_namespace",
    "list_services_from_namespace",
    "list_all_resources",
    "get_deployment_details",
    "get_pod_details",
    "scale_deployment",
    "get_pod_logs",
    "get_resource_health",
    "get_events"
]
