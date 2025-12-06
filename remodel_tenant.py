

"""
1. Retreive tenant attributes from comments
2. Extract IKE/IPSEC details for:
    - ike proposal
    - ike policy
    - ipsec proposal
    - ipsec policy
    - ipsec profile
3. Extract tunnel interface(s) and tunnel prefixes/ips for:
    - Tunnel Group
    - Tunnel(s)
    - Tunnel Termination(s)
"""

from collections import Counter
from django.contrib.contenttypes.models import ContentType
from extras.scripts import *
from extras.models import Tag, CustomField, ExportTemplate
from tenancy.models import Tenant, TenantGroup
from ipam.models import Prefix, IPAddress
from ipam.utils import get_next_available_prefix
from dcim.models import Site, Device, Interface
from users.models import User
from virtualization.models import VirtualMachine
from vpn.models import IKEProposal, IKEPolicy, IPSecProposal, IPSecPolicy, IPSecProfile, Tunnel, TunnelTermination, TunnelGroup
from utilities.exceptions import AbortScript

import datetime
import random
import string
import base64
import json

def parse_tenant_info(tenantData):

    lines = ""
    if ",\r\n" in tenantData:
        lines = tenantData.split("\r\n")
    elif ",\r" in tenantData:
        lines = tenantData.split("\r")
    elif ",\n" in tenantData:
        lines = tenantData.split("\n")
    else:
        return "", "did not recognize new line character"

    inVPN = False
    vpnJSON = {}
    i = 0
    for l in lines:
        lStripped = l
        if lStripped == "===========================" and inVPN == False:
            vpnVars = []
            inVPN = True
            continue
        if inVPN:
            if lStripped == "===========================":
                try:
                    vpnJSON[f"vpnVars_{str(i)}"] = json.loads("".join(vpnVars))
                except Exception as err:
                    print(err)
                    return "", err
                i += 1
                inVPN = False
                continue

            if lStripped == "```" or len(l) == 0 or "VPN Created: " in lStripped:
                continue
            vpnVars.append(lStripped)

    return vpnJSON, ""

def create_tags(tag_name):
    try:
        tag_name = Tag.objects.create(
                    name=f'{tag_name}',
                    slug=f'{tag_name}'
                )
        if tag_name:
            return tag_name
    except Exception as err:
        raise AbortScript(f"Failed to create Tag: {err}")

def create_ip_addr(tenant_name, ip, description, tags):
    try:
        ip_addr = IPAddress.objects.create(
            address = f'{ip}/32',
            description = description,
            status = 'active',
            tenant = Tenant.objects.get(name=tenant_name)
            # tenant_group = TenantGroup.objects.get(name=tenant_group_name)
        )
        if ip_addr:
            ip_addr.tags.set(tags)
            return ip_addr
    except Exception as err:
        raise AbortScript(f"Failed to create IP Address: {err}")

def create_child_prefix(tenant_name, site_id, prefix, cidr_len, description, tags):
    parent_tunnel_prefix_cidr = '169.254.0.0/16'
    parent_dnat_prefix_cidr = '192.168.224.0/19'
    parent = parent_tunnel_prefix_cidr if prefix == 'tunnel' else parent_dnat_prefix_cidr
    parent_prefix = Prefix.objects.get(prefix=parent)

    # Get available prefixes within the parent prefix
    available_tunnel_prefixes = parent_prefix.get_available_prefixes()
    try:
        available_child_tunnel_prefix = get_next_available_prefix(available_tunnel_prefixes, int(cidr_len))
        new_prefix = Prefix.objects.create(
            prefix=available_child_tunnel_prefix,
            site=Site.objects.get(id=site_id),
            tenant=Tenant.objects.get(name=tenant_name),
            status='active',
            description=description
        )
        if new_prefix:
            new_prefix.tags.set(tags)
            return new_prefix
    except Exception as err:
        raise AbortScript(f"Failed to create Tunnel prefix: {err}")

def create_ike_proposal(tenant_name, auth_algo, enc_algo, group, sa_lifetime, tags):
    try:
        ike_proposal = IKEProposal.objects.create(
            name=f'{tenant_name}_ike-proposal', 
            authentication_method='preshared-keys', 
            authentication_algorithm=auth_algo, 
            encryption_algorithm=enc_algo, 
            group=group,
            sa_lifetime=sa_lifetime
        )
        if ike_proposal:
            ike_proposal.tags.set(tags)
            return ike_proposal
    except Exception as err:
        raise AbortScript(f"Failed to create IKE Proposal: {err}")

def create_ike_policy(tenant_name, version, ike_proposal, tags):
    try:
        ike_policy = IKEPolicy.objects.create(
            name=f'{tenant_name}_ike-policy',
            version=version,
            mode='main'
        )
        IKEPolicy.objects.get(name=ike_policy).proposals.set([ike_proposal.id])
        
        if ike_policy:
            ike_policy.tags.set(tags)
            return ike_policy
    except Exception as err:
        raise AbortScript(f"Failed to create IKE Policy: {err}")
    
def create_ipsec_proposal(tenant_name, auth_algo, enc_algo, sa_lifetime, tags):
    try:
        ipsec_proposal = IPSecProposal.objects.create(
            name=f'{tenant_name}_ipsec-proposal',
            authentication_algorithm=auth_algo,
            encryption_algorithm=enc_algo,
            sa_lifetime_seconds=sa_lifetime
        )
        if ipsec_proposal:
            ipsec_proposal.tags.set(tags)
            return ipsec_proposal
    except Exception as err:
        raise AbortScript(f"Failed to create IPSec Proposal: {err}")

def create_ipsec_policy(tenant_name, pfs_group, ipsec_proposal, tags):
    try:
        ipsec_policy = IPSecPolicy.objects.create(
            name=f'{tenant_name}_ipsec-policy',
            pfs_group=pfs_group
        )
        IPSecPolicy.objects.get(name=ipsec_policy).proposals.set([ipsec_proposal.id])
        
        if ipsec_policy:
            ipsec_policy.tags.set(tags)
            return ipsec_policy
    except Exception as err:
        raise AbortScript(f"Failed to create IPSec Policy: {err}")
    
def create_ipsec_profile(tenant_name, ike_policy, ipsec_policy, tags):
    try:
        ipsec_profile = IPSecProfile.objects.create(
            name=f'{tenant_name}_ipsec-profile',
            mode='main',
            ike_policy=IKEPolicy.objects.get(name=ike_policy),
            ipsec_policy=IPSecPolicy.objects.get(name=ipsec_policy)
        )
        if ipsec_profile:
            ipsec_profile.tags.set(tags)
            return ipsec_profile
    except Exception as err:
        raise AbortScript(f"Failed to create IPSec profile: {err}")
    
def create_tunnel_group(tenant_group_name, tags):
    try:
        tunnel_group = TunnelGroup.objects.create(
            name=f'{tenant_group_name}_tunnel-group',
            slug=f'{tenant_group_name}_tunnel-group'
        )
        if tunnel_group:
            tunnel_group.tags.set({tags[0]})
            return tunnel_group
    except Exception as err:
        raise AbortScript(f"Failed to create Tunnel Group: {err}")

def create_tunnel(tunnel_name, tenant, tunnel_group, ipsec_profile, tags):
    try:
        tunnel = Tunnel.objects.create(
            name=tunnel_name,
            tenant=tenant,
            status='planned',
            group=tunnel_group,
            encapsulation='ipsec-tunnel',
            ipsec_profile=ipsec_profile,
            tunnel_id='1'
        )
        if tunnel:
            tunnel.tags.set(tags)
            return tunnel
    except Exception as err:
        raise AbortScript(f"Failed to create Tunnel: {err}")
    
def create_tunnel_termination(tunnel, tags):
    try:
        tunnel_termination = TunnelTermination.objects.create(
            tunnel=tunnel,
            role='peer',
            termination_type=ContentType.objects.get(model='device'),
        )
        if tunnel_termination:
            tunnel_termination.tags.set(tags)
            return tunnel_termination
    except Exception as err:
        raise AbortScript(f"Failed to create Tunnel Termination: {err}")

def create_tunnel_interface(self, description, tunnel_addr_itential, tunnel_addr_client, tunnel_termination, device_name, tags):
    device = Device.objects.get(name=device_name)
    interfaces = Interface.objects.filter(name__startswith='st0.')
    int_list = []
    
    for i in interfaces:
        int_list.append(int(i.name.split(".")[1]))
        
    # remove duplicates
    int_list = set(int_list)
    int_list_uniq = list(int_list)
    # order numbers
    int_list_uniq.sort()

    def find_gaps(input_list):
        prev_item = 0
        for i in input_list:
            if i == 0:
                continue
            if int(i) != prev_item + 1:
                return str(prev_item + 1)
            prev_item = i
        return 0
    
    interface_gap = find_gaps(int_list_uniq)

    if interface_gap == 0:
        new_interface_unit = int(list(Interface.objects.filter(tags=tags[1].id))[0].name.split(".")[1]) if 'Secondary Tunnel Interface' in description and str(device.site.region) == 'us-west-2' else int(int_list_uniq[-1]) +1
    else:
        self.log_info('else')
        new_interface_unit = int(list(Interface.objects.filter(tags=tags[1].id))[0].name.split(".")[1]) if 'Secondary Tunnel Interface' in description and str(device.site.region) == 'us-west-2' else int(interface_gap)
        
    new_interface = "st0.%d" % new_interface_unit

    try:
        interface = Interface.objects.create(
            device=device,
            name=f'{new_interface}',
            type='virtual',
            description=description
        )
        if interface:
            interface.tags.set(tags)
            interface.ip_addresses.set([tunnel_addr_itential, tunnel_addr_client])
            interface.tunnel_terminations.set([tunnel_termination])
            return interface
    except Exception as err:
        raise AbortScript(f"Failed to create Interface: {err}")

class RemodelTenant(Script):
    class Meta:
        name = "Remodel Tenant"
        description = "Create Tenant Models from Variables"
        commit_default = False
        scheduling_enabled = False
        
    tenant_name = ObjectVar(
        label="Tenant Name",
        description="",
        model=Tenant,
        query_params={
            'status': 'active'
        }
    )
    
    def run(self, data, commit):
        
        saas_site_id = Site.objects.get(id=2)
        tunnel_cidr_len = 30
        primary_device_name = 'vsrx-use2-01'# update if device names change in dev/prod
        secondary_device_name = 'vsrx-usw2-01' # update if device names change in dev/prod
        tenant_name = data['tenant_name']
        tenant = Tenant.objects.get(name=tenant_name)
        tenant_group = tenant.group
        tenant_group_name = tenant.group.name
        comments = tenant.comments
        tenant_info = parse_tenant_info(comments)[0]['vpnVars_0']
        
        # dictionaries to convert netbox values to junos values :(
        ike_dh_group = {
            "group1": 1,
            "group2": 2,
            "group5": 5,
            "group14": 14,
            "group15": 15
        }
        ike_auth_algo_choices = {
            "sha1": "hmac-sha1",
            "sha-256": "hmac-sha256",
            "sha-384": "hmac-sha384",
            "sha-512": "hmac-sha512"
        }
        ipsec_pfs_group = {
            "group1": "1",
            "group2": "2",
            "group5": "5",
            "group14": "14",
            "group15": "15"
        }
        ipsec_auth_algo_choices = {
            "hmac-sha1-96": "hmac-sha1",
            "hmac-sha-256-128": "hmac-sha256",
            "hmac-sha-384": "hmac-sha384",
            "hmac-sha-512": "hmac-sha512"
        }
        
        # Existing Tenant Info
        redundancy_type = tenant_info.get('redundancyType', '')
        ike_auth_algo = ike_auth_algo_choices[tenant_info.get('p1AuthAlgo', '')]
        ike_enc_algo = tenant_info.get('p1EncAlgo', '')
        ike_dh_group = ike_dh_group[tenant_info.get('p1DHGroup', '')]
        ike_sa_lifetime = tenant_info.get('p1Lifetime', '')
        ike_version = tenant_info.get('p1IKEVer', '')
        ipsec_auth_algo = ipsec_auth_algo_choices[tenant_info.get('p2AuthAlgo', '')]
        ipsec_enc_algo = tenant_info.get('p2EncAlgo', '')
        ipsec_sa_lifetime = tenant_info.get('p2Lifetime', '')
        ipsec_pfs_group = ipsec_pfs_group[tenant_info.get('pfsEnabled', '')]
        primary_tunnel_prefix = tenant_info.get('tunnelPrefix', '')
        secondary_tunnel_prefix = tenant_info.get('backupTunnelPrefix', '')
        vpn_name = tenant_info.get('vpnName', '')
        primary_vpn_ip = tenant_info.get('clientVPNPeer', '')
        secondary_vpn_ip = tenant_info.get('clientSecondVPNPeer', '')
        primary_tunnel_interface = tenant_info.get('tunnInt', '')
        snat_ip = tenant_info.get('iapSNATIP', '')
        nat_traversal = tenant_info.get('natTraversal', False)
        dnat_dict = tenant_info.get('dnatDict', '')
        itentialPrimaryTunnIP = tenant_info.get('itentialPrimaryTunnIP', '')
        clientPrimaryTunnIP = tenant_info.get('clientPrimaryTunnIP', '')
        clientBackupTunnIP = tenant_info.get('clientBackupTunnIP', '')
        itentialBackupTunnIP = tenant_info.get('itentialBackupTunnIP', '')
        policy_based_vpn = tenant_info.get('policyBased', '')
        bgp_routing = tenant_info.get('bgpEnabled', '')
        bgp_itential_asn = tenant_info.get('itentialASN', '')
        bgp_client_primary_asn = tenant_info.get('clientPrimaryASN', '')
        bgp_client_secondary_asn = tenant_info.get('clientBackupASN', '')
        bgp_routes = ', '.join(tenant_info.get('bgpImportRoutes', ''))
        dnat_prefixes = tenant_info.get('clientDNATNetsCIDR', '')
        secondary_tunnel_interface = tenant_info.get('backupTunnInt', '')
        client_real_networks = ', '.join(tenant_info.get('clientRealNet', ''))
        primaryIntID = tenant_info.get('primaryIntID', '')
        PSK = tenant_info.get('PSK', '')
        primaryFWIP = tenant_info.get('primaryFWIP', '')
        tunnelPrefix = tenant_info.get('tunnelPrefix', '')
        dnatNetboxID = tenant_info.get('dnatNetboxID', '')
        config_template = tenant_info.get('configTemplate', '')
        tenant_id = tenant_info.get('tenantID', '')
        update_time = tenant_info.get('updateTime', '')
        client_name = tenant_info.get('clientName', '')
        addNewDNAT = tenant_info.get('addNewDNAT', '')
        
        # Current Tenant Info
        tenant.custom_field_data["vpn_name"] = vpn_name
        tenant.custom_field_data["primary_vpn_ip"] = primary_vpn_ip
        tenant.custom_field_data["secondary_vpn_ip"] = secondary_vpn_ip 
        tenant.custom_field_data["redundancy_type"] = redundancy_type
        tenant.custom_field_data["nat_traversal"] = nat_traversal
        tenant.custom_field_data["policy_based_vpn"] = policy_based_vpn
        tenant.custom_field_data["snat_ip"] = snat_ip
        tenant.custom_field_data["bgp_routing"] = bgp_routing
        tenant.custom_field_data["bgp_itential_asn"] = bgp_itential_asn
        tenant.custom_field_data["bgp_client_primary_asn"] = bgp_client_primary_asn
        tenant.custom_field_data["bgp_client_secondary_asn"] = bgp_client_secondary_asn
        tenant.custom_field_data["bgp_routes"] = bgp_routes
        tenant.custom_field_data["client_real_networks"] = client_real_networks
        tenant.save()
        
        # Create Tags
        if not Tag.objects.filter(name=tenant_group_name).exists():
            tenant_group_name_tag = create_tags(tenant_group_name)
            tenant_name_tag = create_tags(tenant_name)
            tags = [tenant_group_name_tag, tenant_name_tag]
            tenant_group.tags.set({tenant_group_name_tag})
            tenant.tags.set(tags)
            self.log_success(f"Created Tags for Tenant: ({tenant_group_name_tag})")
        else:
            tenant_group_name_tag = Tag.objects.get(name=tenant_group_name)
            tenant_name_tag = create_tags(tenant_name)
            tags = [tenant_group_name_tag, tenant_name_tag]
            tenant_group.tags.set({tenant_group_name_tag})
            tenant.tags.set(tags)
            
        ## Create Primary Tunnel Prefix
        tunnel_ips_description = {
                        'Itential': f'Primary Tunnel IP: {tenant_name}',
                        'Client': f'Primary Tunnel IP: {tenant_name}'
        }
        
        primary_tunnel_prefix_desc = f'{tenant_name} - Primary Tunnel Prefix'
        primary_child_tunnel_prefix = Prefix.objects.create(prefix=primary_tunnel_prefix,
                                                                        tenant=tenant,
                                                                        status='active',
                                                                        description=primary_tunnel_prefix_desc)
        if primary_child_tunnel_prefix:
            primary_child_tunnel_prefix.tags.set(tags)
            saas_site_id.prefixes.add(primary_child_tunnel_prefix)
            self.log_success(f"Created a new /{tunnel_cidr_len} Primary Tunnel prefix: ({primary_child_tunnel_prefix})")
        
        if redundancy_type in ('1x2', '2x2'):

            tunnel_ips_description = {
                'Itential': f'Secondary Tunnel IP: {tenant_name}',
                'Client': f'Secondary Tunnel IP: {tenant_name}'
            }

            secondary_tunnel_prefix_desc = f'{tenant_name} - Secondary Tunnel Prefix'
            secondary_child_tunnel_prefix = Prefix.objects.create(prefix=secondary_tunnel_prefix,
                                                                        tenant=tenant,
                                                                        status='active',
                                                                        description=secondary_tunnel_prefix_desc)
            
            if secondary_child_tunnel_prefix:
                secondary_child_tunnel_prefix.tags.set(tags)
                saas_site_id.prefixes.add(secondary_child_tunnel_prefix)
                self.log_success(f"Created a new /{tunnel_cidr_len} Secondary Tunnel prefix: ({secondary_child_tunnel_prefix})")
        
        primary_tunnel_ip_itential = IPAddress.objects.create(
            address = itentialPrimaryTunnIP,
            description = f'Itential Primary Tunnel IP: {tenant_name}',
            status = 'active',
            tenant = Tenant.objects.get(name=tenant_name)
            # tenant_group = TenantGroup.objects.get(name=tenant_group_name)
        )
        primary_tunnel_ip_itential.tags.set(tags)
        
        primary_tunnel_ip_client = IPAddress.objects.create(
            address = clientPrimaryTunnIP,
            description = f'Client Primary Tunnel IP: {tenant_name}',
            status = 'active',
            tenant = Tenant.objects.get(name=tenant_name)
            # tenant_group = TenantGroup.objects.get(name=tenant_group_name)
        )
        primary_tunnel_ip_client.tags.set(tags)
        
        if redundancy_type in ('1x2', '2x2'):
            secondary_tunnel_ip_itential = IPAddress.objects.create(
                address = itentialBackupTunnIP,
                description = f'Itential Primary Tunnel IP: {tenant_name}',
                status = 'active',
                tenant = Tenant.objects.get(name=tenant_name)
                # tenant_group = TenantGroup.objects.get(name=tenant_group_name)
            )
            secondary_tunnel_ip_itential.tags.set(tags)
            
            secondary_tunnel_ip_client = IPAddress.objects.create(
                address = clientBackupTunnIP,
                description = f'Client Primary Tunnel IP: {tenant_name}',
                status = 'active',
                tenant = Tenant.objects.get(name=tenant_name)
                # tenant_group = TenantGroup.objects.get(name=tenant_group_name)
            )
            secondary_tunnel_ip_client.tags.set(tags)
            
        ## Create IKE Proposal
        ike_proposal = create_ike_proposal(tenant_name, ike_auth_algo, 
                                           ike_enc_algo, ike_dh_group, 
                                           ike_sa_lifetime, tags)
        self.log_success(f"Created IKE Proposal: ({ike_proposal})")

        ## Create IKE Policy
        ike_policy = create_ike_policy(tenant_name, ike_version, ike_proposal, tags)
        self.log_success(f"Created IKE Policy: ({ike_policy})")

        ## Create IPSec Proposal
        ipsec_proposal = create_ipsec_proposal(tenant_name, ipsec_auth_algo, 
                                               ipsec_enc_algo, ipsec_sa_lifetime, tags)
        self.log_success(f"Created IPSec Proposal: ({ipsec_proposal})")

        ## Create IPSec Policy
        ipsec_policy = create_ipsec_policy(tenant_name, ipsec_pfs_group, ipsec_proposal, tags)
        self.log_success(f"Created IPSec Policy: ({ipsec_policy})")

        ## Create IPSec Profile
        ipsec_profile = create_ipsec_profile(tenant_name, ike_policy, ipsec_policy, tags)
        self.log_success(f"Created IPSec Profile: ({ipsec_profile})")

        ## Create Tunnel Group Object
        if TunnelGroup.objects.filter(name=f'{tenant_group_name}_tunnel-group').exists():
            tunnel_group = TunnelGroup.objects.get(name=f'{tenant_group_name}_tunnel-group')
            self.log_info(f"Tunnel Group already exists: ({tenant_group_name}_tunnel-group)")
        else:
            tunnel_group = create_tunnel_group(tenant_group_name, tags)
            self.log_success(f"Created Tunnel Group: ({tunnel_group})")

        ## Create Primary Tunnel
        primary_tunnel_name = f'{tenant_name}_primary-tunnel'
        primary_tunnel = create_tunnel(primary_tunnel_name, tenant, tunnel_group, ipsec_profile, tags)
        self.log_success(f"Created Primary Tunnel: ({primary_tunnel})")

        ## Create Primary Tunnel Termination
        primary_tunnel_termination = create_tunnel_termination(primary_tunnel, tags)
        self.log_success(f"Created Primary Tunnel termination: ({primary_tunnel_termination})")
        
         ## Create Primary Tunnel Interface
        primary_interface = Interface.objects.create(
            device=Device.objects.get(name=primary_device_name),
            name=f'{primary_tunnel_interface}',
            type='virtual',
            description=f'Primary Tunnel Interface - {tenant_name}'
        )
        if primary_interface:
            primary_interface.tags.set(tags)
            primary_interface.ip_addresses.set([primary_tunnel_ip_itential, primary_tunnel_ip_client])
            primary_interface.tunnel_terminations.set([primary_tunnel_termination])
            self.log_success(f"Created Primary Interface: ({primary_interface.name})")

        # Create Secondary Tunnel (if necessary)
        if redundancy_type in ('1x2', '2x2'):
            device_name = primary_device_name if redundancy_type in ('1x2') else secondary_device_name
            ## Create Secondary Tunnel
            secondary_tunnel_name = f'{tenant_name}_secondary-tunnel'
            secondary_tunnel = create_tunnel(secondary_tunnel_name, tenant, tunnel_group, ipsec_profile, tags)
            self.log_success(f"Created Secondary Tunnel: ({secondary_tunnel})")

            ## Create Secondary Tunnel Termination
            secondary_tunnel_termination = create_tunnel_termination(secondary_tunnel, tags)
            self.log_success(f"Created Secondary Tunnel termination: ({secondary_tunnel_termination})")
            
            ## Create Secondary Tunnel Interface
            secondary_interface = Interface.objects.create(device=Device.objects.get(name=device_name),
                                                name=f'{secondary_tunnel_interface}',
                                                type='virtual',
                                                description=f'Secondary Tunnel Interface - {tenant_name}')
            if secondary_interface:
                secondary_interface.tags.set(tags)
                secondary_interface.ip_addresses.set([secondary_tunnel_ip_itential, secondary_tunnel_ip_client])
                secondary_interface.tunnel_terminations.set([secondary_tunnel_termination])
                self.log_success(f"Created Secondary Interface: ({secondary_interface.name})")
                
        # Create DNAT Prefix
        for dnat_prefix in dnat_prefixes:
            new_child_dnat_prefix = Prefix.objects.create(prefix=dnat_prefix,
                                                        tenant=tenant,
                                                        status='active',
                                                        description=f"{tenant_name} - DNAT Prefix")
            if new_child_dnat_prefix:
                new_child_dnat_prefix.tags.set(tags)
                saas_site_id.prefixes.add(new_child_dnat_prefix)
                self.log_success(f"Created a new /{tunnel_cidr_len} Primary Tunnel prefix: ({new_child_dnat_prefix})")
                
        # Create DNAT IP Addresses
        for host_ip, values in dnat_dict.items():
            dnat_ip = IPAddress.objects.create(
                address = values["dnatIP"],
                description = values["hostDesc"],
                status = 'active',
                tenant = Tenant.objects.get(name=tenant_name)
                # tenant_group = TenantGroup.objects.get(name=tenant_group_name)
            )
            dnat_ip.tags.set(tags)
            # dnat_ip.tags.set([Tag.objects.get(name=tenant_group_name), Tag.objects.get(name=tenant_name)])
            dnat_ip.dns_name = values.get('hostDNS', '')
            dnat_ip.custom_field_data["client_host_ip"] = host_ip
            dnat_ip.custom_field_data["client_host_port"] = values["hostPort"]
            dnat_ip.save()
            self.log_success(f"Created a new DNAT IP for: ({dnat_ip} - {host_ip} - {dnat_ip.description})")