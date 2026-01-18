# EC2 VPC Management API Coverage Spec (Derived from AWS EC2 model)

Source: `specs/ec2-2016-11-15.normal.json`
Protocol: EC2 Query (Action + Version, XML responses).

## Operations

| Operation | Input Shape | Required Fields | Output Shape |
| --- | --- | --- | --- |
| `AcceptTransitGatewayMulticastDomainAssociations` | `AcceptTransitGatewayMulticastDomainAssociationsRequest` |  | `AcceptTransitGatewayMulticastDomainAssociationsResult` |
| `AcceptTransitGatewayPeeringAttachment` | `AcceptTransitGatewayPeeringAttachmentRequest` | TransitGatewayAttachmentId | `AcceptTransitGatewayPeeringAttachmentResult` |
| `AcceptTransitGatewayVpcAttachment` | `AcceptTransitGatewayVpcAttachmentRequest` | TransitGatewayAttachmentId | `AcceptTransitGatewayVpcAttachmentResult` |
| `AcceptVpcEndpointConnections` | `AcceptVpcEndpointConnectionsRequest` | ServiceId, VpcEndpointIds | `AcceptVpcEndpointConnectionsResult` |
| `AcceptVpcPeeringConnection` | `AcceptVpcPeeringConnectionRequest` | VpcPeeringConnectionId | `AcceptVpcPeeringConnectionResult` |
| `ApplySecurityGroupsToClientVpnTargetNetwork` | `ApplySecurityGroupsToClientVpnTargetNetworkRequest` | ClientVpnEndpointId, VpcId, SecurityGroupIds | `ApplySecurityGroupsToClientVpnTargetNetworkResult` |
| `AssignIpv6Addresses` | `AssignIpv6AddressesRequest` | NetworkInterfaceId | `AssignIpv6AddressesResult` |
| `AssignPrivateNatGatewayAddress` | `AssignPrivateNatGatewayAddressRequest` | NatGatewayId | `AssignPrivateNatGatewayAddressResult` |
| `AssociateDhcpOptions` | `AssociateDhcpOptionsRequest` | DhcpOptionsId, VpcId | `` |
| `AssociateNatGatewayAddress` | `AssociateNatGatewayAddressRequest` | NatGatewayId, AllocationIds | `AssociateNatGatewayAddressResult` |
| `AssociateRouteServer` | `AssociateRouteServerRequest` | RouteServerId, VpcId | `AssociateRouteServerResult` |
| `AssociateRouteTable` | `AssociateRouteTableRequest` | RouteTableId | `AssociateRouteTableResult` |
| `AssociateSecurityGroupVpc` | `AssociateSecurityGroupVpcRequest` | GroupId, VpcId | `AssociateSecurityGroupVpcResult` |
| `AssociateSubnetCidrBlock` | `AssociateSubnetCidrBlockRequest` | SubnetId | `AssociateSubnetCidrBlockResult` |
| `AssociateTransitGatewayMulticastDomain` | `AssociateTransitGatewayMulticastDomainRequest` | TransitGatewayMulticastDomainId, TransitGatewayAttachmentId, SubnetIds | `AssociateTransitGatewayMulticastDomainResult` |
| `AssociateTransitGatewayPolicyTable` | `AssociateTransitGatewayPolicyTableRequest` | TransitGatewayPolicyTableId, TransitGatewayAttachmentId | `AssociateTransitGatewayPolicyTableResult` |
| `AssociateTransitGatewayRouteTable` | `AssociateTransitGatewayRouteTableRequest` | TransitGatewayRouteTableId, TransitGatewayAttachmentId | `AssociateTransitGatewayRouteTableResult` |
| `AssociateVpcCidrBlock` | `AssociateVpcCidrBlockRequest` | VpcId | `AssociateVpcCidrBlockResult` |
| `AttachClassicLinkVpc` | `AttachClassicLinkVpcRequest` | InstanceId, VpcId, Groups | `AttachClassicLinkVpcResult` |
| `AttachInternetGateway` | `AttachInternetGatewayRequest` | InternetGatewayId, VpcId | `` |
| `AttachVpnGateway` | `AttachVpnGatewayRequest` | VpcId, VpnGatewayId | `AttachVpnGatewayResult` |
| `AuthorizeSecurityGroupEgress` | `AuthorizeSecurityGroupEgressRequest` | GroupId | `AuthorizeSecurityGroupEgressResult` |
| `AuthorizeSecurityGroupIngress` | `AuthorizeSecurityGroupIngressRequest` |  | `AuthorizeSecurityGroupIngressResult` |
| `CreateClientVpnRoute` | `CreateClientVpnRouteRequest` | ClientVpnEndpointId, DestinationCidrBlock, TargetVpcSubnetId | `CreateClientVpnRouteResult` |
| `CreateCustomerGateway` | `CreateCustomerGatewayRequest` | Type | `CreateCustomerGatewayResult` |
| `CreateDefaultSubnet` | `CreateDefaultSubnetRequest` |  | `CreateDefaultSubnetResult` |
| `CreateDefaultVpc` | `CreateDefaultVpcRequest` |  | `CreateDefaultVpcResult` |
| `CreateDhcpOptions` | `CreateDhcpOptionsRequest` | DhcpConfigurations | `CreateDhcpOptionsResult` |
| `CreateEgressOnlyInternetGateway` | `CreateEgressOnlyInternetGatewayRequest` | VpcId | `CreateEgressOnlyInternetGatewayResult` |
| `CreateFlowLogs` | `CreateFlowLogsRequest` | ResourceIds, ResourceType | `CreateFlowLogsResult` |
| `CreateInternetGateway` | `CreateInternetGatewayRequest` |  | `CreateInternetGatewayResult` |
| `CreateLocalGatewayRoute` | `CreateLocalGatewayRouteRequest` | LocalGatewayRouteTableId | `CreateLocalGatewayRouteResult` |
| `CreateLocalGatewayRouteTable` | `CreateLocalGatewayRouteTableRequest` | LocalGatewayId | `CreateLocalGatewayRouteTableResult` |
| `CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociation` | `CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociationRequest` | LocalGatewayRouteTableId, LocalGatewayVirtualInterfaceGroupId | `CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociationResult` |
| `CreateLocalGatewayRouteTableVpcAssociation` | `CreateLocalGatewayRouteTableVpcAssociationRequest` | LocalGatewayRouteTableId, VpcId | `CreateLocalGatewayRouteTableVpcAssociationResult` |
| `CreateNatGateway` | `CreateNatGatewayRequest` |  | `CreateNatGatewayResult` |
| `CreateNetworkAcl` | `CreateNetworkAclRequest` | VpcId | `CreateNetworkAclResult` |
| `CreateNetworkAclEntry` | `CreateNetworkAclEntryRequest` | NetworkAclId, RuleNumber, Protocol, RuleAction, Egress | `` |
| `CreateRoute` | `CreateRouteRequest` | RouteTableId | `CreateRouteResult` |
| `CreateRouteServer` | `CreateRouteServerRequest` | AmazonSideAsn | `CreateRouteServerResult` |
| `CreateRouteServerEndpoint` | `CreateRouteServerEndpointRequest` | RouteServerId, SubnetId | `CreateRouteServerEndpointResult` |
| `CreateRouteServerPeer` | `CreateRouteServerPeerRequest` | RouteServerEndpointId, PeerAddress, BgpOptions | `CreateRouteServerPeerResult` |
| `CreateRouteTable` | `CreateRouteTableRequest` | VpcId | `CreateRouteTableResult` |
| `CreateSecurityGroup` | `CreateSecurityGroupRequest` | Description, GroupName | `CreateSecurityGroupResult` |
| `CreateSubnet` | `CreateSubnetRequest` | VpcId | `CreateSubnetResult` |
| `CreateSubnetCidrReservation` | `CreateSubnetCidrReservationRequest` | SubnetId, Cidr, ReservationType | `CreateSubnetCidrReservationResult` |
| `CreateTransitGateway` | `CreateTransitGatewayRequest` |  | `CreateTransitGatewayResult` |
| `CreateTransitGatewayConnect` | `CreateTransitGatewayConnectRequest` | TransportTransitGatewayAttachmentId, Options | `CreateTransitGatewayConnectResult` |
| `CreateTransitGatewayConnectPeer` | `CreateTransitGatewayConnectPeerRequest` | TransitGatewayAttachmentId, PeerAddress, InsideCidrBlocks | `CreateTransitGatewayConnectPeerResult` |
| `CreateTransitGatewayMeteringPolicy` | `CreateTransitGatewayMeteringPolicyRequest` | TransitGatewayId | `CreateTransitGatewayMeteringPolicyResult` |
| `CreateTransitGatewayMeteringPolicyEntry` | `CreateTransitGatewayMeteringPolicyEntryRequest` | TransitGatewayMeteringPolicyId, PolicyRuleNumber, MeteredAccount | `CreateTransitGatewayMeteringPolicyEntryResult` |
| `CreateTransitGatewayMulticastDomain` | `CreateTransitGatewayMulticastDomainRequest` | TransitGatewayId | `CreateTransitGatewayMulticastDomainResult` |
| `CreateTransitGatewayPeeringAttachment` | `CreateTransitGatewayPeeringAttachmentRequest` | TransitGatewayId, PeerTransitGatewayId, PeerAccountId, PeerRegion | `CreateTransitGatewayPeeringAttachmentResult` |
| `CreateTransitGatewayPolicyTable` | `CreateTransitGatewayPolicyTableRequest` | TransitGatewayId | `CreateTransitGatewayPolicyTableResult` |
| `CreateTransitGatewayPrefixListReference` | `CreateTransitGatewayPrefixListReferenceRequest` | TransitGatewayRouteTableId, PrefixListId | `CreateTransitGatewayPrefixListReferenceResult` |
| `CreateTransitGatewayRoute` | `CreateTransitGatewayRouteRequest` | DestinationCidrBlock, TransitGatewayRouteTableId | `CreateTransitGatewayRouteResult` |
| `CreateTransitGatewayRouteTable` | `CreateTransitGatewayRouteTableRequest` | TransitGatewayId | `CreateTransitGatewayRouteTableResult` |
| `CreateTransitGatewayRouteTableAnnouncement` | `CreateTransitGatewayRouteTableAnnouncementRequest` | TransitGatewayRouteTableId, PeeringAttachmentId | `CreateTransitGatewayRouteTableAnnouncementResult` |
| `CreateTransitGatewayVpcAttachment` | `CreateTransitGatewayVpcAttachmentRequest` | TransitGatewayId, VpcId, SubnetIds | `CreateTransitGatewayVpcAttachmentResult` |
| `CreateVpc` | `CreateVpcRequest` |  | `CreateVpcResult` |
| `CreateVpcBlockPublicAccessExclusion` | `CreateVpcBlockPublicAccessExclusionRequest` | InternetGatewayExclusionMode | `CreateVpcBlockPublicAccessExclusionResult` |
| `CreateVpcEncryptionControl` | `CreateVpcEncryptionControlRequest` | VpcId | `CreateVpcEncryptionControlResult` |
| `CreateVpcEndpoint` | `CreateVpcEndpointRequest` | VpcId | `CreateVpcEndpointResult` |
| `CreateVpcEndpointConnectionNotification` | `CreateVpcEndpointConnectionNotificationRequest` | ConnectionNotificationArn, ConnectionEvents | `CreateVpcEndpointConnectionNotificationResult` |
| `CreateVpcEndpointServiceConfiguration` | `CreateVpcEndpointServiceConfigurationRequest` |  | `CreateVpcEndpointServiceConfigurationResult` |
| `CreateVpcPeeringConnection` | `CreateVpcPeeringConnectionRequest` | VpcId | `CreateVpcPeeringConnectionResult` |
| `CreateVpnConnectionRoute` | `CreateVpnConnectionRouteRequest` | DestinationCidrBlock, VpnConnectionId | `` |
| `CreateVpnGateway` | `CreateVpnGatewayRequest` | Type | `CreateVpnGatewayResult` |
| `DeleteClientVpnRoute` | `DeleteClientVpnRouteRequest` | ClientVpnEndpointId, DestinationCidrBlock | `DeleteClientVpnRouteResult` |
| `DeleteCustomerGateway` | `DeleteCustomerGatewayRequest` | CustomerGatewayId | `` |
| `DeleteDhcpOptions` | `DeleteDhcpOptionsRequest` | DhcpOptionsId | `` |
| `DeleteEgressOnlyInternetGateway` | `DeleteEgressOnlyInternetGatewayRequest` | EgressOnlyInternetGatewayId | `DeleteEgressOnlyInternetGatewayResult` |
| `DeleteFlowLogs` | `DeleteFlowLogsRequest` | FlowLogIds | `DeleteFlowLogsResult` |
| `DeleteInternetGateway` | `DeleteInternetGatewayRequest` | InternetGatewayId | `` |
| `DeleteLocalGatewayRoute` | `DeleteLocalGatewayRouteRequest` | LocalGatewayRouteTableId | `DeleteLocalGatewayRouteResult` |
| `DeleteLocalGatewayRouteTable` | `DeleteLocalGatewayRouteTableRequest` | LocalGatewayRouteTableId | `DeleteLocalGatewayRouteTableResult` |
| `DeleteLocalGatewayRouteTableVirtualInterfaceGroupAssociation` | `DeleteLocalGatewayRouteTableVirtualInterfaceGroupAssociationRequest` | LocalGatewayRouteTableVirtualInterfaceGroupAssociationId | `DeleteLocalGatewayRouteTableVirtualInterfaceGroupAssociationResult` |
| `DeleteLocalGatewayRouteTableVpcAssociation` | `DeleteLocalGatewayRouteTableVpcAssociationRequest` | LocalGatewayRouteTableVpcAssociationId | `DeleteLocalGatewayRouteTableVpcAssociationResult` |
| `DeleteNatGateway` | `DeleteNatGatewayRequest` | NatGatewayId | `DeleteNatGatewayResult` |
| `DeleteNetworkAcl` | `DeleteNetworkAclRequest` | NetworkAclId | `` |
| `DeleteNetworkAclEntry` | `DeleteNetworkAclEntryRequest` | NetworkAclId, RuleNumber, Egress | `` |
| `DeleteRoute` | `DeleteRouteRequest` | RouteTableId | `` |
| `DeleteRouteServer` | `DeleteRouteServerRequest` | RouteServerId | `DeleteRouteServerResult` |
| `DeleteRouteServerEndpoint` | `DeleteRouteServerEndpointRequest` | RouteServerEndpointId | `DeleteRouteServerEndpointResult` |
| `DeleteRouteServerPeer` | `DeleteRouteServerPeerRequest` | RouteServerPeerId | `DeleteRouteServerPeerResult` |
| `DeleteRouteTable` | `DeleteRouteTableRequest` | RouteTableId | `` |
| `DeleteSecurityGroup` | `DeleteSecurityGroupRequest` |  | `DeleteSecurityGroupResult` |
| `DeleteSubnet` | `DeleteSubnetRequest` | SubnetId | `` |
| `DeleteSubnetCidrReservation` | `DeleteSubnetCidrReservationRequest` | SubnetCidrReservationId | `DeleteSubnetCidrReservationResult` |
| `DeleteTransitGateway` | `DeleteTransitGatewayRequest` | TransitGatewayId | `DeleteTransitGatewayResult` |
| `DeleteTransitGatewayConnect` | `DeleteTransitGatewayConnectRequest` | TransitGatewayAttachmentId | `DeleteTransitGatewayConnectResult` |
| `DeleteTransitGatewayConnectPeer` | `DeleteTransitGatewayConnectPeerRequest` | TransitGatewayConnectPeerId | `DeleteTransitGatewayConnectPeerResult` |
| `DeleteTransitGatewayMeteringPolicy` | `DeleteTransitGatewayMeteringPolicyRequest` | TransitGatewayMeteringPolicyId | `DeleteTransitGatewayMeteringPolicyResult` |
| `DeleteTransitGatewayMeteringPolicyEntry` | `DeleteTransitGatewayMeteringPolicyEntryRequest` | TransitGatewayMeteringPolicyId, PolicyRuleNumber | `DeleteTransitGatewayMeteringPolicyEntryResult` |
| `DeleteTransitGatewayMulticastDomain` | `DeleteTransitGatewayMulticastDomainRequest` | TransitGatewayMulticastDomainId | `DeleteTransitGatewayMulticastDomainResult` |
| `DeleteTransitGatewayPeeringAttachment` | `DeleteTransitGatewayPeeringAttachmentRequest` | TransitGatewayAttachmentId | `DeleteTransitGatewayPeeringAttachmentResult` |
| `DeleteTransitGatewayPolicyTable` | `DeleteTransitGatewayPolicyTableRequest` | TransitGatewayPolicyTableId | `DeleteTransitGatewayPolicyTableResult` |
| `DeleteTransitGatewayPrefixListReference` | `DeleteTransitGatewayPrefixListReferenceRequest` | TransitGatewayRouteTableId, PrefixListId | `DeleteTransitGatewayPrefixListReferenceResult` |
| `DeleteTransitGatewayRoute` | `DeleteTransitGatewayRouteRequest` | TransitGatewayRouteTableId, DestinationCidrBlock | `DeleteTransitGatewayRouteResult` |
| `DeleteTransitGatewayRouteTable` | `DeleteTransitGatewayRouteTableRequest` | TransitGatewayRouteTableId | `DeleteTransitGatewayRouteTableResult` |
| `DeleteTransitGatewayRouteTableAnnouncement` | `DeleteTransitGatewayRouteTableAnnouncementRequest` | TransitGatewayRouteTableAnnouncementId | `DeleteTransitGatewayRouteTableAnnouncementResult` |
| `DeleteTransitGatewayVpcAttachment` | `DeleteTransitGatewayVpcAttachmentRequest` | TransitGatewayAttachmentId | `DeleteTransitGatewayVpcAttachmentResult` |
| `DeleteVpc` | `DeleteVpcRequest` | VpcId | `` |
| `DeleteVpcBlockPublicAccessExclusion` | `DeleteVpcBlockPublicAccessExclusionRequest` | ExclusionId | `DeleteVpcBlockPublicAccessExclusionResult` |
| `DeleteVpcEncryptionControl` | `DeleteVpcEncryptionControlRequest` | VpcEncryptionControlId | `DeleteVpcEncryptionControlResult` |
| `DeleteVpcEndpointConnectionNotifications` | `DeleteVpcEndpointConnectionNotificationsRequest` | ConnectionNotificationIds | `DeleteVpcEndpointConnectionNotificationsResult` |
| `DeleteVpcEndpointServiceConfigurations` | `DeleteVpcEndpointServiceConfigurationsRequest` | ServiceIds | `DeleteVpcEndpointServiceConfigurationsResult` |
| `DeleteVpcEndpoints` | `DeleteVpcEndpointsRequest` | VpcEndpointIds | `DeleteVpcEndpointsResult` |
| `DeleteVpcPeeringConnection` | `DeleteVpcPeeringConnectionRequest` | VpcPeeringConnectionId | `DeleteVpcPeeringConnectionResult` |
| `DeleteVpnConnectionRoute` | `DeleteVpnConnectionRouteRequest` | DestinationCidrBlock, VpnConnectionId | `` |
| `DeleteVpnGateway` | `DeleteVpnGatewayRequest` | VpnGatewayId | `` |
| `DeregisterTransitGatewayMulticastGroupMembers` | `DeregisterTransitGatewayMulticastGroupMembersRequest` |  | `DeregisterTransitGatewayMulticastGroupMembersResult` |
| `DeregisterTransitGatewayMulticastGroupSources` | `DeregisterTransitGatewayMulticastGroupSourcesRequest` |  | `DeregisterTransitGatewayMulticastGroupSourcesResult` |
| `DescribeClassicLinkInstances` | `DescribeClassicLinkInstancesRequest` |  | `DescribeClassicLinkInstancesResult` |
| `DescribeClientVpnRoutes` | `DescribeClientVpnRoutesRequest` | ClientVpnEndpointId | `DescribeClientVpnRoutesResult` |
| `DescribeCustomerGateways` | `DescribeCustomerGatewaysRequest` |  | `DescribeCustomerGatewaysResult` |
| `DescribeDhcpOptions` | `DescribeDhcpOptionsRequest` |  | `DescribeDhcpOptionsResult` |
| `DescribeEgressOnlyInternetGateways` | `DescribeEgressOnlyInternetGatewaysRequest` |  | `DescribeEgressOnlyInternetGatewaysResult` |
| `DescribeFlowLogs` | `DescribeFlowLogsRequest` |  | `DescribeFlowLogsResult` |
| `DescribeInternetGateways` | `DescribeInternetGatewaysRequest` |  | `DescribeInternetGatewaysResult` |
| `DescribeIpv6Pools` | `DescribeIpv6PoolsRequest` |  | `DescribeIpv6PoolsResult` |
| `DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations` | `DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociationsRequest` |  | `DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociationsResult` |
| `DescribeLocalGatewayRouteTableVpcAssociations` | `DescribeLocalGatewayRouteTableVpcAssociationsRequest` |  | `DescribeLocalGatewayRouteTableVpcAssociationsResult` |
| `DescribeLocalGatewayRouteTables` | `DescribeLocalGatewayRouteTablesRequest` |  | `DescribeLocalGatewayRouteTablesResult` |
| `DescribeNatGateways` | `DescribeNatGatewaysRequest` |  | `DescribeNatGatewaysResult` |
| `DescribeNetworkAcls` | `DescribeNetworkAclsRequest` |  | `DescribeNetworkAclsResult` |
| `DescribeRouteServerEndpoints` | `DescribeRouteServerEndpointsRequest` |  | `DescribeRouteServerEndpointsResult` |
| `DescribeRouteServerPeers` | `DescribeRouteServerPeersRequest` |  | `DescribeRouteServerPeersResult` |
| `DescribeRouteServers` | `DescribeRouteServersRequest` |  | `DescribeRouteServersResult` |
| `DescribeRouteTables` | `DescribeRouteTablesRequest` |  | `DescribeRouteTablesResult` |
| `DescribeSecurityGroupReferences` | `DescribeSecurityGroupReferencesRequest` | GroupId | `DescribeSecurityGroupReferencesResult` |
| `DescribeSecurityGroupRules` | `DescribeSecurityGroupRulesRequest` |  | `DescribeSecurityGroupRulesResult` |
| `DescribeSecurityGroupVpcAssociations` | `DescribeSecurityGroupVpcAssociationsRequest` |  | `DescribeSecurityGroupVpcAssociationsResult` |
| `DescribeSecurityGroups` | `DescribeSecurityGroupsRequest` |  | `DescribeSecurityGroupsResult` |
| `DescribeStaleSecurityGroups` | `DescribeStaleSecurityGroupsRequest` | VpcId | `DescribeStaleSecurityGroupsResult` |
| `DescribeSubnets` | `DescribeSubnetsRequest` |  | `DescribeSubnetsResult` |
| `DescribeTransitGatewayAttachments` | `DescribeTransitGatewayAttachmentsRequest` |  | `DescribeTransitGatewayAttachmentsResult` |
| `DescribeTransitGatewayConnectPeers` | `DescribeTransitGatewayConnectPeersRequest` |  | `DescribeTransitGatewayConnectPeersResult` |
| `DescribeTransitGatewayConnects` | `DescribeTransitGatewayConnectsRequest` |  | `DescribeTransitGatewayConnectsResult` |
| `DescribeTransitGatewayMeteringPolicies` | `DescribeTransitGatewayMeteringPoliciesRequest` |  | `DescribeTransitGatewayMeteringPoliciesResult` |
| `DescribeTransitGatewayMulticastDomains` | `DescribeTransitGatewayMulticastDomainsRequest` |  | `DescribeTransitGatewayMulticastDomainsResult` |
| `DescribeTransitGatewayPeeringAttachments` | `DescribeTransitGatewayPeeringAttachmentsRequest` |  | `DescribeTransitGatewayPeeringAttachmentsResult` |
| `DescribeTransitGatewayPolicyTables` | `DescribeTransitGatewayPolicyTablesRequest` |  | `DescribeTransitGatewayPolicyTablesResult` |
| `DescribeTransitGatewayRouteTableAnnouncements` | `DescribeTransitGatewayRouteTableAnnouncementsRequest` |  | `DescribeTransitGatewayRouteTableAnnouncementsResult` |
| `DescribeTransitGatewayRouteTables` | `DescribeTransitGatewayRouteTablesRequest` |  | `DescribeTransitGatewayRouteTablesResult` |
| `DescribeTransitGatewayVpcAttachments` | `DescribeTransitGatewayVpcAttachmentsRequest` |  | `DescribeTransitGatewayVpcAttachmentsResult` |
| `DescribeTransitGateways` | `DescribeTransitGatewaysRequest` |  | `DescribeTransitGatewaysResult` |
| `DescribeVpcAttribute` | `DescribeVpcAttributeRequest` | Attribute, VpcId | `DescribeVpcAttributeResult` |
| `DescribeVpcBlockPublicAccessExclusions` | `DescribeVpcBlockPublicAccessExclusionsRequest` |  | `DescribeVpcBlockPublicAccessExclusionsResult` |
| `DescribeVpcBlockPublicAccessOptions` | `DescribeVpcBlockPublicAccessOptionsRequest` |  | `DescribeVpcBlockPublicAccessOptionsResult` |
| `DescribeVpcClassicLink` | `DescribeVpcClassicLinkRequest` |  | `DescribeVpcClassicLinkResult` |
| `DescribeVpcClassicLinkDnsSupport` | `DescribeVpcClassicLinkDnsSupportRequest` |  | `DescribeVpcClassicLinkDnsSupportResult` |
| `DescribeVpcEncryptionControls` | `DescribeVpcEncryptionControlsRequest` |  | `DescribeVpcEncryptionControlsResult` |
| `DescribeVpcEndpointAssociations` | `DescribeVpcEndpointAssociationsRequest` |  | `DescribeVpcEndpointAssociationsResult` |
| `DescribeVpcEndpointConnectionNotifications` | `DescribeVpcEndpointConnectionNotificationsRequest` |  | `DescribeVpcEndpointConnectionNotificationsResult` |
| `DescribeVpcEndpointConnections` | `DescribeVpcEndpointConnectionsRequest` |  | `DescribeVpcEndpointConnectionsResult` |
| `DescribeVpcEndpointServiceConfigurations` | `DescribeVpcEndpointServiceConfigurationsRequest` |  | `DescribeVpcEndpointServiceConfigurationsResult` |
| `DescribeVpcEndpointServicePermissions` | `DescribeVpcEndpointServicePermissionsRequest` | ServiceId | `DescribeVpcEndpointServicePermissionsResult` |
| `DescribeVpcEndpointServices` | `DescribeVpcEndpointServicesRequest` |  | `DescribeVpcEndpointServicesResult` |
| `DescribeVpcEndpoints` | `DescribeVpcEndpointsRequest` |  | `DescribeVpcEndpointsResult` |
| `DescribeVpcPeeringConnections` | `DescribeVpcPeeringConnectionsRequest` |  | `DescribeVpcPeeringConnectionsResult` |
| `DescribeVpcs` | `DescribeVpcsRequest` |  | `DescribeVpcsResult` |
| `DescribeVpnGateways` | `DescribeVpnGatewaysRequest` |  | `DescribeVpnGatewaysResult` |
| `DetachClassicLinkVpc` | `DetachClassicLinkVpcRequest` | InstanceId, VpcId | `DetachClassicLinkVpcResult` |
| `DetachInternetGateway` | `DetachInternetGatewayRequest` | InternetGatewayId, VpcId | `` |
| `DetachVpnGateway` | `DetachVpnGatewayRequest` | VpcId, VpnGatewayId | `` |
| `DisableRouteServerPropagation` | `DisableRouteServerPropagationRequest` | RouteServerId, RouteTableId | `DisableRouteServerPropagationResult` |
| `DisableTransitGatewayRouteTablePropagation` | `DisableTransitGatewayRouteTablePropagationRequest` | TransitGatewayRouteTableId | `DisableTransitGatewayRouteTablePropagationResult` |
| `DisableVgwRoutePropagation` | `DisableVgwRoutePropagationRequest` | GatewayId, RouteTableId | `` |
| `DisableVpcClassicLink` | `DisableVpcClassicLinkRequest` | VpcId | `DisableVpcClassicLinkResult` |
| `DisableVpcClassicLinkDnsSupport` | `DisableVpcClassicLinkDnsSupportRequest` |  | `DisableVpcClassicLinkDnsSupportResult` |
| `DisassociateNatGatewayAddress` | `DisassociateNatGatewayAddressRequest` | NatGatewayId, AssociationIds | `DisassociateNatGatewayAddressResult` |
| `DisassociateRouteServer` | `DisassociateRouteServerRequest` | RouteServerId, VpcId | `DisassociateRouteServerResult` |
| `DisassociateRouteTable` | `DisassociateRouteTableRequest` | AssociationId | `` |
| `DisassociateSecurityGroupVpc` | `DisassociateSecurityGroupVpcRequest` | GroupId, VpcId | `DisassociateSecurityGroupVpcResult` |
| `DisassociateSubnetCidrBlock` | `DisassociateSubnetCidrBlockRequest` | AssociationId | `DisassociateSubnetCidrBlockResult` |
| `DisassociateTransitGatewayMulticastDomain` | `DisassociateTransitGatewayMulticastDomainRequest` | TransitGatewayMulticastDomainId, TransitGatewayAttachmentId, SubnetIds | `DisassociateTransitGatewayMulticastDomainResult` |
| `DisassociateTransitGatewayPolicyTable` | `DisassociateTransitGatewayPolicyTableRequest` | TransitGatewayPolicyTableId, TransitGatewayAttachmentId | `DisassociateTransitGatewayPolicyTableResult` |
| `DisassociateTransitGatewayRouteTable` | `DisassociateTransitGatewayRouteTableRequest` | TransitGatewayRouteTableId, TransitGatewayAttachmentId | `DisassociateTransitGatewayRouteTableResult` |
| `DisassociateVpcCidrBlock` | `DisassociateVpcCidrBlockRequest` | AssociationId | `DisassociateVpcCidrBlockResult` |
| `EnableRouteServerPropagation` | `EnableRouteServerPropagationRequest` | RouteServerId, RouteTableId | `EnableRouteServerPropagationResult` |
| `EnableTransitGatewayRouteTablePropagation` | `EnableTransitGatewayRouteTablePropagationRequest` | TransitGatewayRouteTableId | `EnableTransitGatewayRouteTablePropagationResult` |
| `EnableVgwRoutePropagation` | `EnableVgwRoutePropagationRequest` | GatewayId, RouteTableId | `` |
| `EnableVpcClassicLink` | `EnableVpcClassicLinkRequest` | VpcId | `EnableVpcClassicLinkResult` |
| `EnableVpcClassicLinkDnsSupport` | `EnableVpcClassicLinkDnsSupportRequest` |  | `EnableVpcClassicLinkDnsSupportResult` |
| `ExportTransitGatewayRoutes` | `ExportTransitGatewayRoutesRequest` | TransitGatewayRouteTableId, S3Bucket | `ExportTransitGatewayRoutesResult` |
| `GetAssociatedIpv6PoolCidrs` | `GetAssociatedIpv6PoolCidrsRequest` | PoolId | `GetAssociatedIpv6PoolCidrsResult` |
| `GetFlowLogsIntegrationTemplate` | `GetFlowLogsIntegrationTemplateRequest` | FlowLogId, ConfigDeliveryS3DestinationArn, IntegrateServices | `GetFlowLogsIntegrationTemplateResult` |
| `GetRouteServerAssociations` | `GetRouteServerAssociationsRequest` | RouteServerId | `GetRouteServerAssociationsResult` |
| `GetRouteServerPropagations` | `GetRouteServerPropagationsRequest` | RouteServerId | `GetRouteServerPropagationsResult` |
| `GetRouteServerRoutingDatabase` | `GetRouteServerRoutingDatabaseRequest` | RouteServerId | `GetRouteServerRoutingDatabaseResult` |
| `GetSecurityGroupsForVpc` | `GetSecurityGroupsForVpcRequest` | VpcId | `GetSecurityGroupsForVpcResult` |
| `GetSubnetCidrReservations` | `GetSubnetCidrReservationsRequest` | SubnetId | `GetSubnetCidrReservationsResult` |
| `GetTransitGatewayAttachmentPropagations` | `GetTransitGatewayAttachmentPropagationsRequest` | TransitGatewayAttachmentId | `GetTransitGatewayAttachmentPropagationsResult` |
| `GetTransitGatewayMeteringPolicyEntries` | `GetTransitGatewayMeteringPolicyEntriesRequest` | TransitGatewayMeteringPolicyId | `GetTransitGatewayMeteringPolicyEntriesResult` |
| `GetTransitGatewayMulticastDomainAssociations` | `GetTransitGatewayMulticastDomainAssociationsRequest` | TransitGatewayMulticastDomainId | `GetTransitGatewayMulticastDomainAssociationsResult` |
| `GetTransitGatewayPolicyTableAssociations` | `GetTransitGatewayPolicyTableAssociationsRequest` | TransitGatewayPolicyTableId | `GetTransitGatewayPolicyTableAssociationsResult` |
| `GetTransitGatewayPolicyTableEntries` | `GetTransitGatewayPolicyTableEntriesRequest` | TransitGatewayPolicyTableId | `GetTransitGatewayPolicyTableEntriesResult` |
| `GetTransitGatewayPrefixListReferences` | `GetTransitGatewayPrefixListReferencesRequest` | TransitGatewayRouteTableId | `GetTransitGatewayPrefixListReferencesResult` |
| `GetTransitGatewayRouteTableAssociations` | `GetTransitGatewayRouteTableAssociationsRequest` | TransitGatewayRouteTableId | `GetTransitGatewayRouteTableAssociationsResult` |
| `GetTransitGatewayRouteTablePropagations` | `GetTransitGatewayRouteTablePropagationsRequest` | TransitGatewayRouteTableId | `GetTransitGatewayRouteTablePropagationsResult` |
| `GetVpcResourcesBlockingEncryptionEnforcement` | `GetVpcResourcesBlockingEncryptionEnforcementRequest` | VpcId | `GetVpcResourcesBlockingEncryptionEnforcementResult` |
| `ModifyLocalGatewayRoute` | `ModifyLocalGatewayRouteRequest` | LocalGatewayRouteTableId | `ModifyLocalGatewayRouteResult` |
| `ModifyRouteServer` | `ModifyRouteServerRequest` | RouteServerId | `ModifyRouteServerResult` |
| `ModifySecurityGroupRules` | `ModifySecurityGroupRulesRequest` | GroupId, SecurityGroupRules | `ModifySecurityGroupRulesResult` |
| `ModifySubnetAttribute` | `ModifySubnetAttributeRequest` | SubnetId | `` |
| `ModifyTransitGateway` | `ModifyTransitGatewayRequest` | TransitGatewayId | `ModifyTransitGatewayResult` |
| `ModifyTransitGatewayMeteringPolicy` | `ModifyTransitGatewayMeteringPolicyRequest` | TransitGatewayMeteringPolicyId | `ModifyTransitGatewayMeteringPolicyResult` |
| `ModifyTransitGatewayPrefixListReference` | `ModifyTransitGatewayPrefixListReferenceRequest` | TransitGatewayRouteTableId, PrefixListId | `ModifyTransitGatewayPrefixListReferenceResult` |
| `ModifyTransitGatewayVpcAttachment` | `ModifyTransitGatewayVpcAttachmentRequest` | TransitGatewayAttachmentId | `ModifyTransitGatewayVpcAttachmentResult` |
| `ModifyVpcAttribute` | `ModifyVpcAttributeRequest` | VpcId | `` |
| `ModifyVpcBlockPublicAccessExclusion` | `ModifyVpcBlockPublicAccessExclusionRequest` | ExclusionId, InternetGatewayExclusionMode | `ModifyVpcBlockPublicAccessExclusionResult` |
| `ModifyVpcBlockPublicAccessOptions` | `ModifyVpcBlockPublicAccessOptionsRequest` | InternetGatewayBlockMode | `ModifyVpcBlockPublicAccessOptionsResult` |
| `ModifyVpcEncryptionControl` | `ModifyVpcEncryptionControlRequest` | VpcEncryptionControlId | `ModifyVpcEncryptionControlResult` |
| `ModifyVpcEndpoint` | `ModifyVpcEndpointRequest` | VpcEndpointId | `ModifyVpcEndpointResult` |
| `ModifyVpcEndpointConnectionNotification` | `ModifyVpcEndpointConnectionNotificationRequest` | ConnectionNotificationId | `ModifyVpcEndpointConnectionNotificationResult` |
| `ModifyVpcEndpointServiceConfiguration` | `ModifyVpcEndpointServiceConfigurationRequest` | ServiceId | `ModifyVpcEndpointServiceConfigurationResult` |
| `ModifyVpcEndpointServicePayerResponsibility` | `ModifyVpcEndpointServicePayerResponsibilityRequest` | ServiceId, PayerResponsibility | `ModifyVpcEndpointServicePayerResponsibilityResult` |
| `ModifyVpcEndpointServicePermissions` | `ModifyVpcEndpointServicePermissionsRequest` | ServiceId | `ModifyVpcEndpointServicePermissionsResult` |
| `ModifyVpcPeeringConnectionOptions` | `ModifyVpcPeeringConnectionOptionsRequest` | VpcPeeringConnectionId | `ModifyVpcPeeringConnectionOptionsResult` |
| `ModifyVpcTenancy` | `ModifyVpcTenancyRequest` | VpcId, InstanceTenancy | `ModifyVpcTenancyResult` |
| `MoveAddressToVpc` | `MoveAddressToVpcRequest` | PublicIp | `MoveAddressToVpcResult` |
| `RegisterTransitGatewayMulticastGroupMembers` | `RegisterTransitGatewayMulticastGroupMembersRequest` | TransitGatewayMulticastDomainId, NetworkInterfaceIds | `RegisterTransitGatewayMulticastGroupMembersResult` |
| `RegisterTransitGatewayMulticastGroupSources` | `RegisterTransitGatewayMulticastGroupSourcesRequest` | TransitGatewayMulticastDomainId, NetworkInterfaceIds | `RegisterTransitGatewayMulticastGroupSourcesResult` |
| `RejectTransitGatewayMulticastDomainAssociations` | `RejectTransitGatewayMulticastDomainAssociationsRequest` |  | `RejectTransitGatewayMulticastDomainAssociationsResult` |
| `RejectTransitGatewayPeeringAttachment` | `RejectTransitGatewayPeeringAttachmentRequest` | TransitGatewayAttachmentId | `RejectTransitGatewayPeeringAttachmentResult` |
| `RejectTransitGatewayVpcAttachment` | `RejectTransitGatewayVpcAttachmentRequest` | TransitGatewayAttachmentId | `RejectTransitGatewayVpcAttachmentResult` |
| `RejectVpcEndpointConnections` | `RejectVpcEndpointConnectionsRequest` | ServiceId, VpcEndpointIds | `RejectVpcEndpointConnectionsResult` |
| `RejectVpcPeeringConnection` | `RejectVpcPeeringConnectionRequest` | VpcPeeringConnectionId | `RejectVpcPeeringConnectionResult` |
| `ReplaceNetworkAclAssociation` | `ReplaceNetworkAclAssociationRequest` | AssociationId, NetworkAclId | `ReplaceNetworkAclAssociationResult` |
| `ReplaceNetworkAclEntry` | `ReplaceNetworkAclEntryRequest` | NetworkAclId, RuleNumber, Protocol, RuleAction, Egress | `` |
| `ReplaceRoute` | `ReplaceRouteRequest` | RouteTableId | `` |
| `ReplaceRouteTableAssociation` | `ReplaceRouteTableAssociationRequest` | AssociationId, RouteTableId | `ReplaceRouteTableAssociationResult` |
| `ReplaceTransitGatewayRoute` | `ReplaceTransitGatewayRouteRequest` | DestinationCidrBlock, TransitGatewayRouteTableId | `ReplaceTransitGatewayRouteResult` |
| `RevokeSecurityGroupEgress` | `RevokeSecurityGroupEgressRequest` | GroupId | `RevokeSecurityGroupEgressResult` |
| `RevokeSecurityGroupIngress` | `RevokeSecurityGroupIngressRequest` |  | `RevokeSecurityGroupIngressResult` |
| `SearchLocalGatewayRoutes` | `SearchLocalGatewayRoutesRequest` | LocalGatewayRouteTableId | `SearchLocalGatewayRoutesResult` |
| `SearchTransitGatewayMulticastGroups` | `SearchTransitGatewayMulticastGroupsRequest` | TransitGatewayMulticastDomainId | `SearchTransitGatewayMulticastGroupsResult` |
| `SearchTransitGatewayRoutes` | `SearchTransitGatewayRoutesRequest` | TransitGatewayRouteTableId, Filters | `SearchTransitGatewayRoutesResult` |
| `StartVpcEndpointServicePrivateDnsVerification` | `StartVpcEndpointServicePrivateDnsVerificationRequest` | ServiceId | `StartVpcEndpointServicePrivateDnsVerificationResult` |
| `UnassignIpv6Addresses` | `UnassignIpv6AddressesRequest` | NetworkInterfaceId | `UnassignIpv6AddressesResult` |
| `UnassignPrivateNatGatewayAddress` | `UnassignPrivateNatGatewayAddressRequest` | NatGatewayId, PrivateIpAddresses | `UnassignPrivateNatGatewayAddressResult` |
| `UpdateSecurityGroupRuleDescriptionsEgress` | `UpdateSecurityGroupRuleDescriptionsEgressRequest` |  | `UpdateSecurityGroupRuleDescriptionsEgressResult` |
| `UpdateSecurityGroupRuleDescriptionsIngress` | `UpdateSecurityGroupRuleDescriptionsIngressRequest` |  | `UpdateSecurityGroupRuleDescriptionsIngressResult` |