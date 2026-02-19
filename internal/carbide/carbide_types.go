/*
Copyright (c) 2025 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package carbide

//go:generate go tool ogen --target . --package carbide /files/projects/carbide/carbide-rest/repository/openapi/spec.yaml

import (
	"time"
)

type Entity struct {
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

type Tenant struct {
	Entity `json:",inline"`

	Id             string `json:"id"`
	Org            string `json:"org"`
	OrgDisplayName string `json:"orgDisplayName"`
}

// InfrastructureProvider represents an infrastructure provider in the Carbide API.
type InfrastructureProvider struct {
	Entity `json:",inline"`

	Id             string `json:"id"`
	Org            string `json:"org"`
	OrgDisplayName string `json:"orgDisplayName,omitempty"`
}

// ServiceAccount represents the service account status for an org in the Carbide API.
type ServiceAccount struct {
	Enabled                  bool   `json:"enabled"`
	InfrastructureProviderId string `json:"infrastructureProviderId,omitempty"`
	TenantId                 string `json:"tenantId,omitempty"`
}

// Machine represents a machine in the Carbide API.
type Machine struct {
	Entity `json:",inline"`

	Id                       string              `json:"id"`
	InfrastructureProviderId string              `json:"infrastructureProviderId,omitempty"`
	SiteId                   string              `json:"siteId,omitempty"`
	InstanceTypeId           *string             `json:"instanceTypeId,omitempty"`
	InstanceId               *string             `json:"instanceId,omitempty"`
	TenantId                 *string             `json:"tenantId,omitempty"`
	ControllerMachineId      string              `json:"controllerMachineId,omitempty"`
	ControllerMachineType    string              `json:"controllerMachineType,omitempty"`
	HwSkuDeviceType          *string             `json:"hwSkuDeviceType,omitempty"`
	Vendor                   string              `json:"vendor,omitempty"`
	ProductName              string              `json:"productName,omitempty"`
	SerialNumber             string              `json:"serialNumber,omitempty"`
	MachineCapabilities      []MachineCapability `json:"machineCapabilities,omitempty"`
	MachineInterfaces        []MachineInterface  `json:"machineInterfaces,omitempty"`
	MaintenanceMessage       *string             `json:"maintenanceMessage,omitempty"`
	Health                   *MachineHealth      `json:"health,omitempty"`
	Labels                   map[string]string   `json:"labels,omitempty"`
	Status                   string              `json:"status,omitempty"`
	IsUsableByTenant         bool                `json:"isUsableByTenant,omitempty"`
	StatusHistory            []StatusDetail      `json:"statusHistory,omitempty"`
}

// MachineCapability represents a hardware capability of a machine.
type MachineCapability struct {
	Type            string  `json:"type,omitempty"`
	Name            string  `json:"name,omitempty"`
	Frequency       *string `json:"frequency,omitempty"`
	Cores           *int    `json:"cores,omitempty"`
	Threads         *int    `json:"threads,omitempty"`
	Capacity        *string `json:"capacity,omitempty"`
	Vendor          *string `json:"vendor,omitempty"`
	InactiveDevices []int   `json:"inactiveDevices,omitempty"`
	Count           *int    `json:"count,omitempty"`
	DeviceType      *string `json:"deviceType,omitempty"`
}

// MachineInterface represents a network interface of a machine.
type MachineInterface struct {
	Entity `json:",inline"`

	Id                    string   `json:"id,omitempty"`
	MachineId             string   `json:"machineId,omitempty"`
	ControllerInterfaceId string   `json:"controllerInterfaceId,omitempty"`
	ControllerSegmentId   string   `json:"controllerSegmentId,omitempty"`
	SubnetId              *string  `json:"subnetId,omitempty"`
	Hostname              string   `json:"hostname,omitempty"`
	IsPrimary             bool     `json:"isPrimary,omitempty"`
	MacAddress            string   `json:"macAddress,omitempty"`
	IpAddresses           []string `json:"ipAddresses,omitempty"`
}

// MachineHealth represents the health information of a machine.
type MachineHealth struct {
	Source     string                    `json:"source,omitempty"`
	ObservedAt *string                   `json:"observedAt,omitempty"`
	Successes  []MachineHealthProbe      `json:"successes,omitempty"`
	Alerts     []MachineHealthProbeAlert `json:"alerts,omitempty"`
}

// MachineHealthProbe represents a successful health probe result.
type MachineHealthProbe struct {
	Id     string  `json:"id,omitempty"`
	Target *string `json:"target,omitempty"`
}

// MachineHealthProbeAlert represents a failed health probe result.
type MachineHealthProbeAlert struct {
	Id              string   `json:"id,omitempty"`
	Target          *string  `json:"target,omitempty"`
	InAlertSince    *string  `json:"inAlertSince,omitempty"`
	Message         string   `json:"message,omitempty"`
	TenantMessage   *string  `json:"tenantMessage,omitempty"`
	Classifications []string `json:"classifications,omitempty"`
}

// StatusDetail represents a status transition entry.
type StatusDetail struct {
	Entity `json:",inline"`

	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

// Site represents a site in the Carbide API.
type Site struct {
	Entity `json:",inline"`

	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
}

// InstanceType represents an instance type in the Carbide API.
type InstanceType struct {
	Entity `json:",inline"`

	Id                       string `json:"id"`
	Name                     string `json:"name"`
	SiteId                   string `json:"siteId,omitempty"`
	InfrastructureProviderId string `json:"infrastructureProviderId,omitempty"`
	Status                   string `json:"status,omitempty"`
}

// MachineInstanceTypeAssociation contains the data needed to associate machines with an instance type.
type MachineInstanceTypeAssociation struct {
	MachineIds []string `json:"machineIds"`
}

// Allocation represents an allocation linking a tenant to a site in the Carbide API.
type Allocation struct {
	Entity `json:",inline"`

	Id                    string                 `json:"id"`
	Name                  string                 `json:"name"`
	TenantId              string                 `json:"tenantId,omitempty"`
	SiteId                string                 `json:"siteId,omitempty"`
	Status                string                 `json:"status,omitempty"`
	AllocationConstraints []AllocationConstraint `json:"allocationConstraints,omitempty"`
}

// AllocationConstraint represents a resource constraint within an allocation.
type AllocationConstraint struct {
	ResourceType      string  `json:"resourceType"`
	ResourceTypeId    string  `json:"resourceTypeId"`
	ConstraintType    string  `json:"constraintType"`
	ConstraintValue   int     `json:"constraintValue"`
	DerivedResourceId *string `json:"derivedResourceId,omitempty"`
}

// Vpc represents a VPC in the Carbide API.
type Vpc struct {
	Entity `json:",inline"`

	Id                        string `json:"id"`
	Name                      string `json:"name"`
	SiteId                    string `json:"siteId"`
	TenantId                  string `json:"tenantId,omitempty"`
	NetworkVirtualizationType string `json:"networkVirtualizationType,omitempty"`
	Status                    string `json:"status,omitempty"`
}

// IpBlock represents an IP block in the Carbide API.
type IpBlock struct {
	Entity `json:",inline"`

	Id              string `json:"id"`
	Name            string `json:"name"`
	SiteId          string `json:"siteId,omitempty"`
	RoutingType     string `json:"routingType,omitempty"`
	Prefix          string `json:"prefix,omitempty"`
	PrefixLength    int    `json:"prefixLength,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
}

// Subnet represents a subnet in the Carbide API.
type Subnet struct {
	Entity `json:",inline"`

	Id           string `json:"id"`
	Name         string `json:"name"`
	VpcId        string `json:"vpcId,omitempty"`
	Ipv4BlockId  string `json:"ipv4BlockId,omitempty"`
	PrefixLength int    `json:"prefixLength,omitempty"`
	Status       string `json:"status,omitempty"`
}

type VPCPrefix struct {
	Entity `json:",inline"`

	Id           string `json:"id"`
	Name         string `json:"name"`
	SiteId       string `json:"siteId,omitempty"`
	VpcId        string `json:"vpcId,omitempty"`
	IPBlockId    string `json:"ipBlockId,omitempty"`
	Prefix       string `json:"prefix,omitempty"`
	PrefixLength int    `json:"prefixLength,omitempty"`
	Status       string `json:"status,omitempty"`
}

// Instance represents an instance in the Carbide API.
type Instance struct {
	Entity `json:",inline"`

	Id                       string              `json:"id"`
	Name                     string              `json:"name"`
	Description              string              `json:"description,omitempty"`
	TenantId                 string              `json:"tenantId,omitempty"`
	InfrastructureProviderId string              `json:"infrastructureProviderId,omitempty"`
	SiteId                   string              `json:"siteId,omitempty"`
	InstanceTypeId           string              `json:"instanceTypeId,omitempty"`
	VpcId                    string              `json:"vpcId,omitempty"`
	MachineId                string              `json:"machineId,omitempty"`
	OperatingSystemId        string              `json:"operatingSystemId,omitempty"`
	ControllerInstanceId     string              `json:"controllerInstanceId,omitempty"`
	IpxeScript               string              `json:"ipxeScript,omitempty"`
	AlwaysBootWithCustomIpxe bool                `json:"alwaysBootWithCustomIpxe,omitempty"`
	PhoneHomeEnabled         bool                `json:"phoneHomeEnabled,omitempty"`
	UserData                 string              `json:"userData,omitempty"`
	Labels                   map[string]string   `json:"labels,omitempty"`
	IsUpdatePending          bool                `json:"isUpdatePending,omitempty"`
	SerialConsoleUrl         string              `json:"serialConsoleUrl,omitempty"`
	Status                   string              `json:"status,omitempty"`
	StatusHistory            []StatusDetail      `json:"statusHistory,omitempty"`
	Interfaces               []InstanceInterface `json:"interfaces,omitempty"`
	SshKeyGroupIds           []string            `json:"sshKeyGroupIds,omitempty"`
}

// InstanceInterface represents a network interface of an instance.
type InstanceInterface struct {
	SubnetId    string `json:"subnetId,omitempty"`
	VPCPrefixId string `json:"vpcPrefixId,omitempty"`
	IsPhysical  bool   `json:"isPhysical,omitempty"`
}
