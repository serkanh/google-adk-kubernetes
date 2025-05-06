from kubernetes import client, config
from kubernetes.client.rest import ApiException
from typing import Dict, List, Optional, Union
from datetime import datetime
from kubernetes.stream import stream

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

def list_deployments_all_namespaces() -> List[Dict]:
    """
    List deployments across all namespaces.

    Returns:
        List[Dict]: A list of dictionaries, each containing deployment name and namespace.
    """
    try:
        deployments = apps_v1.list_deployment_for_all_namespaces()
        return [
            {
                "name": deploy.metadata.name,
                "namespace": deploy.metadata.namespace,
                "replicas": deploy.spec.replicas,
            }
            for deploy in deployments.items
        ]
    except ApiException as e:
        return [{"error": f"Failed to list deployments across all namespaces: {str(e)}"}]

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

def list_pods_all_namespaces() -> List[Dict]:
    """
    List pods across all namespaces.

    Returns:
        List[Dict]: A list of dictionaries, each containing pod name, namespace, and status.
    """
    try:
        pods = api_v1.list_pod_for_all_namespaces()
        return [
            {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "status": pod.status.phase
            }
            for pod in pods.items
        ]
    except ApiException as e:
        return [{"error": f"Failed to list pods across all namespaces: {str(e)}"}]

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

def get_deployment_details(deployment_name: str, namespace: str = "default") -> Dict:
    """
    Get detailed information about a specific deployment.

    Args:
        deployment_name (str): The name of the deployment.
        namespace (str): The namespace of the deployment. Defaults to "default".

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

def get_pod_details(pod_name: str, namespace: str = "default") -> Dict:
    """
    Get detailed information about a specific pod.

    Args:
        pod_name (str): The name of the pod.
        namespace (str): The namespace of the pod. Defaults to "default".

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

def scale_deployment(deployment_name: str, replicas: int, namespace: str = "default") -> Dict:
    """
    Scale a deployment to a specific number of replicas.

    Args:
        deployment_name (str): The name of the deployment.
        replicas (int): The desired number of replicas.
        namespace (str): The namespace of the deployment. Defaults to "default".

    Returns:
        Dict: Status of the scaling operation.
    """
    try:
        body = {"spec": {"replicas": replicas}}
        apps_v1.patch_namespaced_deployment_scale(deployment_name, namespace, body)
        return {"status": "success", "message": f"Scaled deployment {deployment_name} in namespace {namespace} to {replicas} replicas"}
    except ApiException as e:
        return {"status": "error", "message": f"Failed to scale deployment: {str(e)}"}

def get_pod_logs(pod_name: str, namespace: str = "default", container: Optional[str] = None, tail_lines: int = 100) -> str:
    """
    Get logs from a specific pod.

    Args:
        pod_name (str): The name of the pod.
        namespace (str): The namespace of the pod. Defaults to "default".
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

def get_resource_health(resource_name: str, resource_type: str, namespace: str = "default") -> Dict:
    """
    Get health status of a specific resource.

    Args:
        resource_name (str): Name of the resource.
        resource_type (str): Type of resource (pod, deployment, service).
        namespace (str): The namespace of the resource. Defaults to "default".

    Returns:
        Dict: Health status of the resource.
    """
    try:
        if resource_type == "pod":
            pod = api_v1.read_namespaced_pod(resource_name, namespace)
            # Check if container_statuses is None before summing restart counts
            restart_count = sum(cs.restart_count for cs in pod.status.container_statuses) if pod.status.container_statuses else 0
            return {
                "status": pod.status.phase,
                "ready": all(condition.status == "True" for condition in pod.status.conditions if pod.status.conditions),
                "restart_count": restart_count
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

def _format_k8s_events(events_items: List) -> List[Dict]:
    """Internal helper to format Kubernetes event objects."""
    formatted_events = []
    for event in events_items:
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

def get_events(namespace: str = "default", limit: int = 200) -> List[Dict]:
    """
    Get Kubernetes events for a specific namespace with a configurable limit.

    Args:
        namespace (str): The namespace to get events from. Defaults to "default".
        limit (int): Maximum number of events to return. Default is 200.

    Returns:
        List[Dict]: List of events with their details.
    """
    try:
        events = api_v1.list_namespaced_event(namespace, limit=limit)
        return _format_k8s_events(events.items)
    except ApiException as e:
        return [{"error": f"Failed to get events for namespace {namespace}: {str(e)}"}]

def get_events_all_namespaces(limit: int = 200) -> List[Dict]:
    """
    Get Kubernetes events across all namespaces with a configurable limit.

    Args:
        limit (int): Maximum number of events to return. Default is 200.

    Returns:
        List[Dict]: List of events from all namespaces with their details.
    """
    try:
        events = api_v1.list_event_for_all_namespaces(limit=limit)
        return _format_k8s_events(events.items)
    except ApiException as e:
        return [{"error": f"Failed to get events across all namespaces: {str(e)}"}]

def get_node_status() -> List[Dict]:
    """
    Get detailed status of all nodes including:
    - Resource usage (CPU, Memory)
    - Conditions (Ready, MemoryPressure, DiskPressure, NetworkUnavailable)
    - Pod capacity and allocatable resources
    - Taints and labels
    
    Returns:
        List[Dict]: A list of dictionaries containing detailed information about each node.
    """
    try:
        nodes = api_v1.list_node()
        node_status = []
        
        for node in nodes.items:
            conditions = {}
            for condition in node.status.conditions:
                conditions[condition.type] = {
                    "status": condition.status,
                    "reason": condition.reason,
                    "message": condition.message,
                    "last_transition_time": condition.last_transition_time.isoformat() if condition.last_transition_time else None
                }
            
            taints = []
            if node.spec.taints:
                for taint in node.spec.taints:
                    taints.append({
                        "key": taint.key,
                        "value": taint.value,
                        "effect": taint.effect
                    })
            
            capacity = {
                "cpu": node.status.capacity.get("cpu"),
                "memory": node.status.capacity.get("memory"),
                "pods": node.status.capacity.get("pods")
            }
            
            allocatable = {
                "cpu": node.status.allocatable.get("cpu"),
                "memory": node.status.allocatable.get("memory"),
                "pods": node.status.allocatable.get("pods")
            }
            
            node_info = {
                "name": node.metadata.name,
                "status": {
                    "conditions": conditions,
                    "capacity": capacity,
                    "allocatable": allocatable,
                    "addresses": [{"type": addr.type, "address": addr.address} for addr in node.status.addresses] if node.status.addresses else []
                },
                "spec": {
                    "taints": taints,
                    "unschedulable": node.spec.unschedulable if hasattr(node.spec, "unschedulable") else False
                },
                "metadata": {
                    "labels": node.metadata.labels,
                    "annotations": node.metadata.annotations,
                    "creation_timestamp": node.metadata.creation_timestamp.isoformat() if node.metadata.creation_timestamp else None
                },
                "info": {
                    "architecture": node.status.node_info.architecture,
                    "kernel_version": node.status.node_info.kernel_version,
                    "os_image": node.status.node_info.os_image,
                    "container_runtime_version": node.status.node_info.container_runtime_version,
                    "kubelet_version": node.status.node_info.kubelet_version,
                    "kube_proxy_version": node.status.node_info.kube_proxy_version
                }
            }
            
            node_status.append(node_info)
            
        return node_status
    except ApiException as e:
        return [{"error": f"Failed to get node status: {str(e)}"}]

def get_resource_consumption(namespace: Optional[str] = None) -> Dict:
    """
    Get resource consumption metrics across namespaces or specific namespace:
    - CPU/Memory requests and limits
    - Storage consumption
    - Pod count
    - Compare against quotas
    
    Args:
        namespace (str, optional): The namespace to get resource consumption for.
                                  If None, gets consumption across all namespaces.
    
    Returns:
        Dict: Resource consumption metrics including CPU, memory, storage usage,
              pod counts, and quota comparisons.
    """
    try:
        result = {}
        
        # Get pods to calculate resource requests and limits
        if namespace:
            pods = api_v1.list_namespaced_pod(namespace)
            namespaces_to_check = [namespace]
        else:
            pods = api_v1.list_pod_for_all_namespaces()
            namespaces_list = api_v1.list_namespace()
            namespaces_to_check = [ns.metadata.name for ns in namespaces_list.items]
        
        # Initialize metrics structure
        metrics = {}
        for ns in namespaces_to_check:
            metrics[ns] = {
                "cpu": {
                    "requests": 0,
                    "limits": 0,
                    "quota": None
                },
                "memory": {
                    "requests": 0,
                    "limits": 0,
                    "quota": None
                },
                "storage": {
                    "used": 0,
                    "quota": None
                },
                "pods": {
                    "count": 0,
                    "quota": None
                }
            }
        
        # Calculate resource requests and limits from pods
        for pod in pods.items:
            pod_namespace = pod.metadata.namespace
            if pod_namespace not in metrics:
                continue
                
            metrics[pod_namespace]["pods"]["count"] += 1
            
            for container in pod.spec.containers:
                if container.resources.requests:
                    cpu_request = container.resources.requests.get("cpu")
                    if cpu_request:
                        # Convert CPU requests to a common unit (cores)
                        if cpu_request.endswith("m"):
                            metrics[pod_namespace]["cpu"]["requests"] += int(cpu_request[:-1]) / 1000
                        else:
                            metrics[pod_namespace]["cpu"]["requests"] += float(cpu_request)
                    
                    memory_request = container.resources.requests.get("memory")
                    if memory_request:
                        # Convert memory to a common unit (bytes)
                        if memory_request.endswith("Ki"):
                            metrics[pod_namespace]["memory"]["requests"] += int(memory_request[:-2]) * 1024
                        elif memory_request.endswith("Mi"):
                            metrics[pod_namespace]["memory"]["requests"] += int(memory_request[:-2]) * 1024 * 1024
                        elif memory_request.endswith("Gi"):
                            metrics[pod_namespace]["memory"]["requests"] += int(memory_request[:-2]) * 1024 * 1024 * 1024
                        else:
                            metrics[pod_namespace]["memory"]["requests"] += int(memory_request)
                
                if container.resources.limits:
                    cpu_limit = container.resources.limits.get("cpu")
                    if cpu_limit:
                        if cpu_limit.endswith("m"):
                            metrics[pod_namespace]["cpu"]["limits"] += int(cpu_limit[:-1]) / 1000
                        else:
                            metrics[pod_namespace]["cpu"]["limits"] += float(cpu_limit)
                    
                    memory_limit = container.resources.limits.get("memory")
                    if memory_limit:
                        if memory_limit.endswith("Ki"):
                            metrics[pod_namespace]["memory"]["limits"] += int(memory_limit[:-2]) * 1024
                        elif memory_limit.endswith("Mi"):
                            metrics[pod_namespace]["memory"]["limits"] += int(memory_limit[:-2]) * 1024 * 1024
                        elif memory_limit.endswith("Gi"):
                            metrics[pod_namespace]["memory"]["limits"] += int(memory_limit[:-2]) * 1024 * 1024 * 1024
                        else:
                            metrics[pod_namespace]["memory"]["limits"] += int(memory_limit)
        
        # Get PVCs to calculate storage usage
        for ns in namespaces_to_check:
            pvcs = api_v1.list_namespaced_persistent_volume_claim(ns)
            for pvc in pvcs.items:
                if pvc.spec.resources.requests and pvc.spec.resources.requests.get("storage"):
                    storage = pvc.spec.resources.requests.get("storage")
                    if storage.endswith("Ki"):
                        metrics[ns]["storage"]["used"] += int(storage[:-2]) * 1024
                    elif storage.endswith("Mi"):
                        metrics[ns]["storage"]["used"] += int(storage[:-2]) * 1024 * 1024
                    elif storage.endswith("Gi"):
                        metrics[ns]["storage"]["used"] += int(storage[:-2]) * 1024 * 1024 * 1024
                    else:
                        metrics[ns]["storage"]["used"] += int(storage)
        
        # Get resource quotas for comparison
        for ns in namespaces_to_check:
            quotas = api_v1.list_namespaced_resource_quota(ns)
            for quota in quotas.items:
                if quota.spec.hard:
                    if quota.spec.hard.get("cpu"):
                        metrics[ns]["cpu"]["quota"] = quota.spec.hard.get("cpu")
                    if quota.spec.hard.get("memory"):
                        metrics[ns]["memory"]["quota"] = quota.spec.hard.get("memory")
                    if quota.spec.hard.get("pods"):
                        metrics[ns]["pods"]["quota"] = int(quota.spec.hard.get("pods"))
                    if quota.spec.hard.get("requests.storage"):
                        metrics[ns]["storage"]["quota"] = quota.spec.hard.get("requests.storage")
        
        # Format the result
        if namespace:
            result = metrics.get(namespace, {})
        else:
            result = {
                "namespaces": metrics,
                "total": {
                    "cpu": {
                        "requests": sum(ns["cpu"]["requests"] for ns in metrics.values()),
                        "limits": sum(ns["cpu"]["limits"] for ns in metrics.values())
                    },
                    "memory": {
                        "requests": sum(ns["memory"]["requests"] for ns in metrics.values()),
                        "limits": sum(ns["memory"]["limits"] for ns in metrics.values())
                    },
                    "storage": {
                        "used": sum(ns["storage"]["used"] for ns in metrics.values())
                    },
                    "pods": {
                        "count": sum(ns["pods"]["count"] for ns in metrics.values())
                    }
                }
            }
        
        return result
    except ApiException as e:
        return {"error": f"Failed to get resource consumption: {str(e)}"}

def diagnose_network_connectivity(pod_name: str, namespace: str, target: str) -> Dict:
    """
    Execute network diagnostics:
    - DNS resolution checks
    - Service connectivity tests
    - NetworkPolicy validation
    - Ingress/Egress route validation
    
    Args:
        pod_name (str): The name of the pod to diagnose from.
        namespace (str): The namespace of the pod.
        target (str): The target to test connectivity to (can be a service name, IP, or domain).
    
    Returns:
        Dict: Results of network diagnostics including DNS resolution, connectivity tests,
              NetworkPolicy validation, and routing information.
    """
    try:
        results = {
            "pod": pod_name,
            "namespace": namespace,
            "target": target,
            "dns_resolution": None,
            "connectivity": None,
            "network_policies": [],
            "routes": {}
        }
        
        # DNS resolution check
        dns_command = f"nslookup {target}"
        dns_exec_response = stream(api_v1.connect_get_namespaced_pod_exec,
            pod_name,
            namespace,
            command=['/bin/sh', '-c', dns_command],
            stderr=True, stdin=False,
            stdout=True, tty=False,
            _preload_content=False)
        dns_output = ""
        while dns_exec_response.is_open():
            dns_exec_response.update(timeout=1)
            if dns_exec_response.peek_stdout():
                dns_output += dns_exec_response.read_stdout()
            if dns_exec_response.peek_stderr():
                 # Handle or log stderr if necessary
                 dns_output += dns_exec_response.read_stderr() # Capture stderr too
        dns_exec_response.close()

        results["dns_resolution"] = {
            "command": dns_command,
            "success": "Name:" in dns_output or "Address:" in dns_output,
            "output": dns_output.strip() # Use the captured output
        }
        
        # Connectivity test with wget or curl
        conn_command = f"timeout 5 curl -s -o /dev/null -w '%{{http_code}}' {target} || echo 'Connection failed'"
        conn_output = ""
        try:
            # Use stream
            conn_exec_response = stream(api_v1.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                command=['/bin/sh', '-c', conn_command],
                stderr=True, stdin=False,
                stdout=True, tty=False,
                _preload_content=False)
            while conn_exec_response.is_open():
                 conn_exec_response.update(timeout=1)
                 if conn_exec_response.peek_stdout():
                     conn_output += conn_exec_response.read_stdout()
                 if conn_exec_response.peek_stderr():
                     conn_output += conn_exec_response.read_stderr()
            conn_exec_response.close()

            results["connectivity"] = {
                "command": conn_command,
                "success": conn_output != "Connection failed" and "command not found" not in conn_output,
                "output": conn_output.strip()
            }
        except Exception as curl_err:
            # Try with wget if curl fails
            conn_command = f"timeout 5 wget -q -O /dev/null {target} && echo 'Success' || echo 'Connection failed'"
            conn_output_wget = ""
            # Use stream
            conn_exec_response_wget = stream(api_v1.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                command=['/bin/sh', '-c', conn_command],
                stderr=True, stdin=False,
                stdout=True, tty=False,
                _preload_content=False)
            while conn_exec_response_wget.is_open():
                conn_exec_response_wget.update(timeout=1)
                if conn_exec_response_wget.peek_stdout():
                    conn_output_wget += conn_exec_response_wget.read_stdout()
                if conn_exec_response_wget.peek_stderr():
                    conn_output_wget += conn_exec_response_wget.read_stderr()
            conn_exec_response_wget.close()

            results["connectivity"] = {
                "command": conn_command,
                "success": "Success" in conn_output_wget,
                "output": conn_output_wget.strip(),
                "previous_error": str(curl_err) # Include previous error info
            }
        
        # NetworkPolicy validation
        network_policies = client.NetworkingV1Api().list_namespaced_network_policy(namespace)
        for policy in network_policies.items:
            policy_info = {
                "name": policy.metadata.name,
                "pod_selector": policy.spec.pod_selector.match_labels if policy.spec.pod_selector else {},
                "policy_types": policy.spec.policy_types if hasattr(policy.spec, "policy_types") else [],
                "ingress_rules": [],
                "egress_rules": []
            }
            
            # Check ingress rules
            if hasattr(policy.spec, "ingress") and policy.spec.ingress:
                for rule in policy.spec.ingress:
                    rule_info = {"from": []}
                    if hasattr(rule, "from") and rule.from_:
                        for item in rule.from_:
                            if hasattr(item, "pod_selector") and item.pod_selector:
                                rule_info["from"].append({
                                    "pod_selector": item.pod_selector.match_labels
                                })
                            if hasattr(item, "namespace_selector") and item.namespace_selector:
                                rule_info["from"].append({
                                    "namespace_selector": item.namespace_selector.match_labels
                                })
                            if hasattr(item, "ip_block") and item.ip_block:
                                rule_info["from"].append({
                                    "ip_block": {
                                        "cidr": item.ip_block.cidr,
                                        "except": item.ip_block.except_ if hasattr(item.ip_block, "except_") else []
                                    }
                                })
                    policy_info["ingress_rules"].append(rule_info)
            
            # Check egress rules
            if hasattr(policy.spec, "egress") and policy.spec.egress:
                for rule in policy.spec.egress:
                    rule_info = {"to": []}
                    if hasattr(rule, "to") and rule.to:
                        for item in rule.to:
                            if hasattr(item, "pod_selector") and item.pod_selector:
                                rule_info["to"].append({
                                    "pod_selector": item.pod_selector.match_labels
                                })
                            if hasattr(item, "namespace_selector") and item.namespace_selector:
                                rule_info["to"].append({
                                    "namespace_selector": item.namespace_selector.match_labels
                                })
                            if hasattr(item, "ip_block") and item.ip_block:
                                rule_info["to"].append({
                                    "ip_block": {
                                        "cidr": item.ip_block.cidr,
                                        "except": item.ip_block.except_ if hasattr(item.ip_block, "except_") else []
                                    }
                                })
                    policy_info["egress_rules"].append(rule_info)
            
            results["network_policies"].append(policy_info)
        
        # Get routing information
        route_command = "ip route"
        route_output = ""
        try:
             # Use stream
            route_exec_response = stream(api_v1.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                command=['/bin/sh', '-c', route_command],
                stderr=True, stdin=False,
                stdout=True, tty=False,
                _preload_content=False)
            while route_exec_response.is_open():
                route_exec_response.update(timeout=1)
                if route_exec_response.peek_stdout():
                    route_output += route_exec_response.read_stdout()
                if route_exec_response.peek_stderr():
                    route_output += route_exec_response.read_stderr()
            route_exec_response.close()

            results["routes"]["ip_routes"] = route_output.strip().split("\\n") if route_output else []
        except Exception as route_err:
            results["routes"]["ip_routes"] = [f"Failed to get IP routes: {str(route_err)}"]
        
        # Get service information if target appears to be a service
        if "." not in target or (target.count(".") == 1 and target.endswith(f".{namespace}")):
            try:
                service_name = target.split(".")[0]
                service = api_v1.read_namespaced_service(service_name, namespace)
                results["service_info"] = {
                    "name": service.metadata.name,
                    "type": service.spec.type,
                    "cluster_ip": service.spec.cluster_ip,
                    "ports": [{"port": port.port, "target_port": port.target_port, "protocol": port.protocol} 
                             for port in service.spec.ports] if service.spec.ports else []
                }
            except ApiException:
                results["service_info"] = {"error": f"Service {target} not found or not accessible"}
        
        return results
    except ApiException as e:
        return {"error": f"Failed to diagnose network connectivity: {str(e)}"}

def list_nodes(include_labels: bool = False, include_ips: bool = False) -> List[Union[str, Dict]]:
    """
    List nodes in the cluster. Optionally include labels and IP addresses.

    Args:
        include_labels (bool): Whether to include node labels in the output. Defaults to False.
        include_ips (bool): Whether to include node internal IP addresses. Defaults to False.

    Returns:
        List[Union[str, Dict]]: A list of node names (str) or dictionaries containing
                                node name, labels, and/or IPs if requested.
    """
    try:
        nodes = api_v1.list_node()
        result = []
        for node in nodes.items:
            if include_labels or include_ips:
                node_info = {"name": node.metadata.name}
                if include_labels:
                    node_info["labels"] = node.metadata.labels
                if include_ips:
                    internal_ip = "N/A"
                    for addr in node.status.addresses:
                        if addr.type == "InternalIP":
                            internal_ip = addr.address
                            break
                    node_info["internal_ip"] = internal_ip
                result.append(node_info)
            else:
                result.append(node.metadata.name)
        return result
    except ApiException as e:
        # Return the error message in a list for consistency
        return [f"Error listing nodes: {str(e)}"]

def get_pods_on_node(node_name: str) -> List[Dict]:
    """
    List all pods running on a specific node.

    Args:
        node_name (str): The name of the node to filter pods by.

    Returns:
        List[Dict]: A list of dictionaries, each containing the pod's name and namespace.
                    Returns an error dictionary if the operation fails.
    """
    try:
        field_selector = f'spec.nodeName={node_name}'
        pods = api_v1.list_pod_for_all_namespaces(field_selector=field_selector)
        return [
            {"name": pod.metadata.name, "namespace": pod.metadata.namespace}
            for pod in pods.items
        ]
    except ApiException as e:
        return [{"error": f"Failed to get pods on node {node_name}: {str(e)}"}]

__all__ = [
    "list_namespaces",
    "list_deployments_from_namespace",
    "list_deployments_all_namespaces",
    "list_pods_from_namespace",
    "list_pods_all_namespaces",
    "list_services_from_namespace",
    "list_secrets_from_namespace",
    "list_daemonsets_from_namespace",
    "list_configmaps_from_namespace",
    "list_all_resources",
    "get_deployment_details",
    "get_pod_details",
    "scale_deployment",
    "get_pod_logs",
    "get_resource_health",
    "get_events",
    "get_events_all_namespaces",
    "get_node_status",
    "get_resource_consumption",
    "diagnose_network_connectivity",
    "list_nodes",
    "get_pods_on_node"
] 
