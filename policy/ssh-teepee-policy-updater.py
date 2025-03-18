#!/usr/bin/env python3
import psycopg2
import os
import ipaddress
import httpx
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# Database connection details (use environment variables for security)
DB_HOST = os.getenv("DB_HOST", "your-db-host")
DB_NAME = os.getenv("DB_NAME", "your-db-name")
DB_USER = os.getenv("DB_USER", "your-db-user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "your-db-password")

# Discord webhook URL (from environment variable)
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Query to fetch IP addresses from ssh_connections
QUERY = "SELECT client_ip FROM ssh_connections WHERE client_ip IS NOT NULL"

# Namespace where ingress-nginx lives
NAMESPACE = "ingress-nginx"  # Adjust if different
POLICY_NAME = "deny-ssh-ips-to-ingress-nginx"

def fetch_ip_addresses():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cur = conn.cursor()
        cur.execute(QUERY)
        rows = cur.fetchall()
        ip_list = [normalize_ip(row[0]) for row in rows]
        cur.close()
        conn.close()
        return ip_list
    except Exception as e:
        print(f"Error fetching IPs: {e}")
        return []

def normalize_ip(ip):
    """Normalize IP addresses: IPv4-mapped to pure IPv4, IPv6 preserved."""
    try:
        if "/" in ip:
            base_ip, cidr = ip.split("/", 1)
        else:
            base_ip, cidr = ip, None

        ip_obj = ipaddress.ip_address(base_ip)

        if ip_obj.version == 4:
            return f"{ip_obj}/32" if cidr is None else f"{ip_obj}/{cidr}"
        elif ip_obj.version == 6:
            if base_ip.startswith("::ffff:"):
                ipv4_str = base_ip.replace("::ffff:", "")
                ipv4_obj = ipaddress.ip_address(ipv4_str)
                if ipv4_obj.version == 4:
                    return f"{ipv4_obj}/32" if cidr is None else f"{ipv4_obj}/{cidr}"
            return f"{ip_obj}/128" if cidr is None else f"{ip_obj}/{cidr}"
    except ValueError:
        print(f"Skipping invalid IP address: {ip}")
        return None

def generate_cilium_policy(ip_list):
    valid_ips = [ip for ip in ip_list if ip is not None]
    if not valid_ips:
        print("No valid IP addresses to include in policy.")
        return None
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": POLICY_NAME,
            "namespace": NAMESPACE
        },
        "spec": {
            "endpointSelector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "ingress-nginx"
                }
            },
            "ingressDeny": [
                {
                    "fromCIDR": valid_ips
                }
            ]
        }
    }

def send_discord_message(message):
    """Send a message to Discord via webhook using httpx."""
    if not DISCORD_WEBHOOK_URL:
        print("DISCORD_WEBHOOK_URL not set. Skipping Discord notification.")
        return
    payload = {
        "content": message,
        "username": "Cilium Policy Bot"  # Optional: customize bot name
    }
    try:
        with httpx.Client() as client:
            response = client.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10.0)
            response.raise_for_status()
        print("Discord message sent successfully.")
    except httpx.HTTPStatusError as e:
        print(f"Failed to send Discord message: HTTP {e.response.status_code} - {e.response.text}")
    except httpx.RequestError as e:
        print(f"Failed to send Discord message: {e}")

def apply_policy(policy):
    if policy is None:
        print("No policy to apply due to lack of valid IPs.")
        return False
    config.load_incluster_config()
    custom_api = client.CustomObjectsApi()
    success = False

    try:
        custom_api.patch_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=NAMESPACE,
            plural="ciliumnetworkpolicies",
            name=POLICY_NAME,
            body=policy
        )
        print("Cilium Network Policy updated successfully.")
        success = True
    except ApiException as e:
        if e.status == 404:
            try:
                custom_api.create_namespaced_custom_object(
                    group="cilium.io",
                    version="v2",
                    namespace=NAMESPACE,
                    plural="ciliumnetworkpolicies",
                    body=policy
                )
                print("Cilium Network Policy created successfully.")
                success = True
            except ApiException as create_error:
                print(f"Error creating policy: {create_error}")
        else:
            print(f"Error updating policy: {e}")
    
    if success:
        ip_count = len(policy["spec"]["ingressDeny"][0]["fromCIDR"])
        send_discord_message(f"Cilium Network Policy '{POLICY_NAME}' updated with {ip_count} IPs.")
    return success

if __name__ == "__main__":
    ip_list = fetch_ip_addresses()
    if not ip_list:
        print("No IP addresses found. Exiting without applying policy.")
        send_discord_message("No IP addresses found in ssh_connections. Policy not updated.")
        exit(0)
    policy = generate_cilium_policy(ip_list)
    apply_policy(policy)
