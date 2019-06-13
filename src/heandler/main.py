from kubernetes import client, config
from kubernetes.client.rest import ApiException
import os
import json
import hashlib
import boto3
import botocore

try:
    aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID']
    aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']
    ec2_region = os.environ['EC2_REGION']
    configmap_name = os.environ['CONFIGMAP_NAME']
    security_group_name = os.environ['SECURITY_GROUP_NAME']
except Exception as e:
    print("miss env: %s\n" % e)
    os._exit(1)

ingress_ports = [ 80 ]
namespace = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()


def get_kube_nodes_ip(kube_client):
    data, ip_list = [], []
    try:                 
        nodes = kube_client.list_node(limit=10)
        for item in nodes.items:
            for addresses in item.status.addresses:
                if addresses.type == 'ExternalIP':
                    data.append(addresses.address + '/32')
        ip_list = sorted(data)
        ip_list_str = '\n'.join(ip_list)

        # get md5 sum of ip_list_str
        m = hashlib.md5()
        m.update(ip_list_str)
        ip_list_hash = m.hexdigest()

        return ip_list, ip_list_str, ip_list_hash

    except ApiException as e:
        print("Exception when calling CoreV1Api->read_node: %s\n" % e)

def get_current_configmap_value(kube_client):
    configmap_value, current_value = None, None
    try:
        configmap_value = kube_client.read_namespaced_config_map(configmap_name, namespace)
        print("current configmap value: %s " % configmap_value)
    except ApiException as e:
        print("Exception when calling CoreV1Api->read_namespaced_config_map: %s\n" % e)

    if configmap_value:
        if configmap_value.data and 'checksum' in configmap_value.data:
            current_value = configmap_value.data['checksum']

    return current_value

def create_configmap_object(ip_list_str,ip_list_hash):
    # Configureate ConfigMap metadata
    metadata = client.V1ObjectMeta(
        name = configmap_name,
        namespace = namespace,
    )
    # Instantiate the configmap object
    configmap = client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        data=dict(ips=ip_list_str,checksum=ip_list_hash),
        metadata=metadata
    )
    return configmap

def create_configmap(kube_client, configmap):
    try:
        api_response = kube_client.create_namespaced_config_map(
            namespace = namespace,
            body = configmap,
            pretty = 'pretty_example'
        )
        print(api_response)
    except ApiException as e:
        print("Exception when calling CoreV1Api->create_namespaced_config_map: %s\n" % e)

def replace_configmap(kube_client, configmap):
    try:
        api_response = kube_client.replace_namespaced_config_map(
            name = configmap_name,
            namespace = namespace,
            body = configmap,
            pretty = 'pretty_example'
        )
        print(api_response)

    except ApiException as e:
        print("Exception when calling CoreV1Api->replace_namespaced_config_map: %s\n" % e)

def update_security_groups(ip_list):
    client = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=ec2_region
        )
    
    groups = get_security_groups_for_update(client)
    print("Found %s SecurityGroups to update" % str(len(groups)))
 
    result = []
    updated = 0
    
    for group in groups:
        if update_security_group(client, group, ip_list):
            updated += 1
            result.append('Updated ' + group['GroupId'])
    
    result.append('Updated ' + str(updated) + ' of ' + str(len(groups)) + ' SecurityGroups')

    return result

def get_security_groups_for_update(client):
    filters = list();
    # Tags which identify the security groups you want to update
    SECURITY_GROUP_TAGS = { 'Name': security_group_name }

    for key, value in SECURITY_GROUP_TAGS.iteritems():
        filters.extend(
            [
                { 'Name': "tag-key", 'Values': [ key ] },
                { 'Name': "tag-value", 'Values': [ value ] }
            ]
        )
 
    response = client.describe_security_groups(Filters=filters)
    
    return response['SecurityGroups']

def update_security_group(client, group, ip_list):
    added = 0
    removed = 0
 
    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if ingress_ports.count(permission['ToPort']) > 0:
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                for range in permission['IpRanges']:
                    cidr = range['CidrIp']
                    old_prefixes.append(cidr)
                    if ip_list.count(cidr) == 0:
                        to_revoke.append(range)
                        print("%s : Revoking %s : %s" % (group['GroupId'], cidr, str(permission['ToPort'])))
            
                for range in ip_list:
                    if old_prefixes.count(range) == 0:
                        to_add.append({ 'CidrIp': range })
                        print("%s : Adding %s : %s" % (group['GroupId'], range, str(permission['ToPort'])))
            
                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add)
    else:
        for port in ingress_ports:
            to_add = list()
            for range in new_ranges:
                to_add.append({ 'CidrIp': range })
                print("%s : Adding %s : %s" % (group['GroupId'], range, str(port)))
            permission = { 'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
            added += add_permissions(client, group, permission, to_add)
 
    print("%s : Added %s, Revoked %s" % (group['GroupId'], str(added), str(removed)))
    return (added > 0 or removed > 0)

def add_permissions(client, group, permission, to_add):
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }
        
        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])
        
    return len(to_add)

def revoke_permissions(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }
        
        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])
        
    return len(to_revoke)

def main():
    config.load_incluster_config()
    kube_client = client.CoreV1Api()

    # get kube node ip
    ip_list, ip_list_str, ip_list_hash = get_kube_nodes_ip(kube_client)
    if not ip_list:
        print("cannot get kube nodes ip")
        os._exit(1)

    # get the current value of the ConfigMap
    current_value = get_current_configmap_value(kube_client)

    if current_value is None:
        # create a configmap
        print("configmap not found, create it.")
        configmap = create_configmap_object(ip_list_str, ip_list_hash)
        create_configmap(kube_client, configmap)
        update_security_groups(ip_list)

    elif current_value != ip_list_hash:
        # kube nodes ip was change, replace the configmap
        print("update configmap")
        configmap = create_configmap_object(ip_list_str, ip_list_hash)
        replace_configmap(kube_client, configmap)
        update_security_groups(ip_list)
    else:
        print("success")

if __name__ == '__main__':
    main()
