from google.adk.agents import Agent
from .tools.tools import *

root_agent = Agent(
    name="kubernetes_assistant",
    model="gemini-2.0-flash-exp",
    instruction="You are a helpful assistant. Who can perform tasks of Kubernetes cluster management such as listing namespaces, deployments, pods, and services. Answer the user's questions using the tools available and present response in Markdown format.",
    description="An assistant that can help you with your Kubernetes cluster",
    tools=[
        list_namespaces, 
        list_deployments_from_namespace, 
        list_deployments_all_namespaces,
        list_pods_from_namespace, 
        list_pods_all_namespaces,
        list_services_from_namespace, 
        list_secrets_from_namespace,
        list_daemonsets_from_namespace,
        list_configmaps_from_namespace,
        list_all_resources, 
        get_deployment_details, 
        get_pod_details, 
        scale_deployment, 
        get_pod_logs, 
        get_resource_health, 
        get_events,
        get_events_all_namespaces,
        get_node_status,
        get_resource_consumption,
        diagnose_network_connectivity,
        list_nodes,
        get_pods_on_node
    ],
)
