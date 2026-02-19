/*
Copyright (c) 2025 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package cmd

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osac-project/fulfillment-common/auth"
	"github.com/osac-project/fulfillment-common/network"
	"github.com/osac-project/fulfillment-common/oauth"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/osac-project/fulfillment-service/internal"
	"github.com/osac-project/fulfillment-service/internal/carbide"
	internalhealth "github.com/osac-project/fulfillment-service/internal/health"
	"github.com/osac-project/fulfillment-service/internal/jq"
	shtdwn "github.com/osac-project/fulfillment-service/internal/shutdown"
	"github.com/osac-project/fulfillment-service/internal/version"
)

// NewStartCarbideSyncCmd creates and returns the `start controllers` command.
func NewStartCarbideSyncCmd() *cobra.Command {
	runner := &startCarbideSyncRunner{}
	command := &cobra.Command{
		Use:   "carbide-sync",
		Short: "Starts the carbide sync",
		Args:  cobra.NoArgs,
		RunE:  runner.run,
	}
	flags := command.Flags()
	flags.StringArrayVar(
		&runner.args.caFiles,
		"ca-file",
		[]string{},
		"File or directory containing trusted CA certificates.",
	)
	flags.StringVar(
		&runner.args.issuer,
		"issuer",
		"",
		"URL of the issuer to use for authentication.",
	)
	flags.StringVar(
		&runner.args.endpoint,
		"endpoint",
		"",
		"URL of the endpoint to use for connecting to the Carbide API.",
	)

	network.AddGrpcClientFlags(flags, network.GrpcClientName, network.DefaultGrpcAddress)
	network.AddListenerFlags(flags, network.GrpcListenerName, network.DefaultGrpcAddress)
	network.AddListenerFlags(flags, network.MetricsListenerName, network.DefaultMetricsAddress)
	return command
}

// startCarbideSyncRunner contains the data and logic needed to run the `start carbide sync` command.
type startCarbideSyncRunner struct {
	logger         *slog.Logger
	flags          *pflag.FlagSet
	jqTool         *jq.Tool
	caPool         *x509.CertPool
	tenantClient   *carbide.Client
	providerClient *carbide.Client
	adminClient    *carbide.Client
	args           struct {
		caFiles  []string
		issuer   string
		endpoint string
	}

	// Tenant credentials (loaded from Kubernetes secret)
	tenantClientId     string
	tenantClientSecret string
	tenantOrgId        string
	tenantScopes       string
	// Kubernetes client for reading secrets
	kubeClient client.Client
	// Operation flow (SSA or provider)
	flow string
}

// run runs the `start carbide sync` command.
func (r *startCarbideSyncRunner) run(cmd *cobra.Command, argv []string) error {
	var err error

	// Get the context:
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// Get the dependencies from the context:
	r.logger = internal.LoggerFromContext(ctx)

	// Get the operation flow from environment variable:
	r.flow = os.Getenv(flowEnv)

	r.logger.InfoContext(ctx, "Using operation flow",
		slog.String("flow", r.flow),
	)

	// Save the flags:
	r.flags = cmd.Flags()

	// Create the JQ tool:
	r.jqTool, err = jq.NewTool().
		SetLogger(r.logger).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create JQ tool: %w", err)
	}

	// Create the shutdown sequence:
	r.logger.InfoContext(ctx, "Creating shutdown sequence")
	shutdown, err := shtdwn.NewSequence().
		SetLogger(r.logger).
		AddSignals(syscall.SIGTERM, syscall.SIGINT).
		AddContext("context", 0, cancel).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create shutdown sequence: %w", err)
	}

	// Load the trusted CA certificates:
	r.logger.InfoContext(ctx, "Loading trusted CA certificates")
	r.caPool, err = network.NewCertPool().
		SetLogger(r.logger).
		AddFiles(r.args.caFiles...).
		Build()
	if err != nil {
		return fmt.Errorf("failed to load trusted CA certificates: %w", err)
	}

	// Create in-cluster Kubernetes client for reading secrets:
	r.logger.InfoContext(ctx, "Creating Kubernetes client")
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get in-cluster config: %w", err)
	}
	r.kubeClient, err = client.New(kubeConfig, client.Options{})
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Load tenant credentials from Kubernetes secret:
	r.logger.InfoContext(ctx, "Loading tenant credentials from Kubernetes secret")
	err = r.loadTenantCredentialsFromSecret(ctx)
	if err != nil {
		return fmt.Errorf("failed to load tenant credentials from secret: %w", err)
	}

	// Create the gRPC server:
	r.logger.InfoContext(ctx, "Creating gRPC listener")
	grpcListener, err := network.NewListener().
		SetLogger(r.logger).
		SetFlags(r.flags, network.GrpcListenerName).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	grpcServer := grpc.NewServer()
	shutdown.AddGrpcServer(network.GrpcListenerName, 0, grpcServer)

	// Register the reflection server:
	r.logger.InfoContext(ctx, "Registering gRPC reflection server")
	reflection.RegisterV1(grpcServer)

	// Register the health server:
	r.logger.InfoContext(ctx, "Registering gRPC health server")
	healthServer := health.NewServer()
	healthv1.RegisterHealthServer(grpcServer, healthServer)

	// Create the health aggregator:
	r.logger.InfoContext(ctx, "Creating health aggregator")
	_, err = internalhealth.NewAggregator().
		SetLogger(r.logger).
		SetServer(healthServer).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create health aggregator: %w", err)
	}

	// Start the gRPC server:
	r.logger.InfoContext(
		ctx,
		"Starting gRPC server",
		slog.String("address", grpcListener.Addr().String()),
	)
	go func() {
		err := grpcServer.Serve(grpcListener)
		if err != nil {
			r.logger.ErrorContext(
				ctx,
				"gRPC server failed",
				slog.Any("error", err),
			)
		}
	}()

	// Create the metrics listener:
	r.logger.InfoContext(ctx, "Creating metrics listener")
	metricsListener, err := network.NewListener().
		SetLogger(r.logger).
		SetFlags(r.flags, network.MetricsListenerName).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create metrics listener: %w", err)
	}

	// Start the metrics server:
	r.logger.InfoContext(
		ctx,
		"Starting metrics server",
		slog.String("address", metricsListener.Addr().String()),
	)
	metricsServer := &http.Server{
		Handler: promhttp.Handler(),
	}
	go func() {
		err := metricsServer.Serve(metricsListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.logger.ErrorContext(
				ctx,
				"Metrics server failed",
				slog.Any("error", err),
			)
		}
	}()

	// Create the tenant client using user-provided credentials.
	// This client acts on behalf of the tenant/customer.
	r.tenantClient, err = r.createTenantClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create tenant Carbide API client: %w", err)
	}

	// Get the details of the current tenant:
	var tenant carbide.Tenant
	err = r.tenantClient.Get().
		SetEndpoint("tenant", "current").
		SetOutput(&tenant).
		Send(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current tenant: %w", err)
	}
	r.logger.InfoContext(
		ctx,
		"Current tenant",
		slog.Any("details", tenant),
	)

	// Find the site:
	site, err := r.findSite(ctx)
	if err != nil {
		return fmt.Errorf("failed to find site: %w", err)
	}

	var instanceType *carbide.InstanceType
	var tenantIpBlock *carbide.IpBlock

	var setupClient *carbide.Client

	if r.flow != flowSSA {
		// Create the provider and admin clients using service credentials.
		// These clients are used for infrastructure management operations.
		r.providerClient, err = r.createClient(ctx, "provider@example.com", "providerpassword")
		if err != nil {
			return fmt.Errorf("failed to create provider Carbide API client: %w", err)
		}

		setupClient = r.providerClient

	} else {
		setupClient = r.tenantClient
	}

	instanceType, tenantIpBlock, err = r.setup(ctx, setupClient, site.Id, tenant.Id)
	if err != nil {
		return fmt.Errorf("failed to perform setup: %w", err)
	}

	r.logger.InfoContext(
		ctx,
		"Tenant setup complete",
		slog.String("instance_type", instanceType.Id),
		slog.String("tenant_ip_block", tenantIpBlock.Id),
	)

	// Ensure the VPC exists:
	vpc, err := r.ensureVpc(ctx, site.Id)
	if err != nil {
		return fmt.Errorf("failed to ensure VPC exists: %w", err)
	}
	r.logger.InfoContext(
		ctx,
		"Using VPC",
		slog.String("id", vpc.Id),
		slog.String("name", vpc.Name),
		slog.String("status", vpc.Status),
	)

	// Ensure the network resource (VPC prefix or subnet) exists based on VPC type:
	networkID, err := r.ensureNetworkResource(ctx, vpc, tenantIpBlock.Id)
	if err != nil {
		return fmt.Errorf("failed to ensure network resource exists: %w", err)
	}

	// Ensure the instance exists and is ready:
	instance, err := r.ensureInstance(ctx, tenant.Id, instanceType.Id, networkID, vpc)
	if err != nil {
		return fmt.Errorf("failed to ensure instance exists: %w", err)
	}

	r.logger.InfoContext(
		ctx,
		"Instance is ready",
		slog.String("id", instance.Id),
		slog.String("name", instance.Name),
		slog.String("status", instance.Status),
	)

	// Wait for the shutdown sequence to complete:
	r.logger.InfoContext(
		ctx,
		"Waiting for shutdown sequence to complete",
	)
	return shutdown.Wait()
}

// providerSetup performs the provider-side setup for the site. It lists machines, creates the instance type and
// allocation, and creates the IP block with its allocation. It returns the list of machines and the derived
// tenant IP block.
func (r *startCarbideSyncRunner) setup(ctx context.Context, client *carbide.Client, siteId,
	tenantId string) (instanceType *carbide.InstanceType, tenantIpBlock *carbide.IpBlock, err error) {

	// Create the instance type if it doesn't exist:
	instanceType, err = r.ensureInstanceType(ctx, client, siteId)
	if err != nil {
		err = fmt.Errorf("failed to ensure instance type exists: %w", err)
		return
	}

	if r.flow != flowSSA {
		// Get the list of machines for the site:
		var machines []carbide.Machine
		err = client.Get().
			SetEndpoint("machine").
			SetQueryParameter("siteId", siteId).
			SetOutput(&machines).
			Send(ctx)
		if err != nil {
			err = fmt.Errorf("failed to get list of machines: %w", err)
			return
		}
		for _, machine := range machines {
			r.logger.InfoContext(
				ctx,
				"Found machine",
				slog.String("id", machine.Id),
				slog.String("status", machine.Status),
			)
		}

		// Associate all machines with the instance type:
		machineIds := make([]string, len(machines))
		for i, machine := range machines {
			machineIds[i] = machine.Id
		}
		r.logger.InfoContext(
			ctx,
			"Associating machines with instance type",
			slog.String("instance_type", instanceType.Id),
			slog.Int("size", len(machineIds)),
		)
		err = client.Post().
			SetEndpoint("instance", "type", instanceType.Id, "machine").
			SetInput(&carbide.MachineInstanceTypeAssociation{
				MachineIds: machineIds,
			}).
			Send(ctx)
		if err != nil {
			err = fmt.Errorf("failed to associate machines with instance type: %w", err)
			return
		}
	}

	// // Create the allocation that allows the user to use the instance type:
	_, err = r.ensureAllocation(ctx, client, siteId, tenantId, instanceType.Id)
	if err != nil {
		err = fmt.Errorf("failed to ensure allocation exists: %w", err)
		return
	}

	// Ensure the provider IP block exists for the site:
	providerIpBlock, err := r.ensureIpBlock(ctx, client, siteId, tenantId)
	if err != nil {
		err = fmt.Errorf("failed to ensure provider IP block exists: %w", err)
		return
	}

	// Ensure the IP block allocation exists, deriving a tenant IP block from the provider IP block:
	tenantIpBlock, err = r.ensureIpBlockAllocation(ctx, client, siteId, tenantId, providerIpBlock.Id)
	if err != nil {
		err = fmt.Errorf("failed to ensure IP block allocation exists: %w", err)
		return
	}

	return
}

// ensureInstanceType checks if the expected instance type exists for the site and creates it if it doesn't.
func (r *startCarbideSyncRunner) ensureInstanceType(
	ctx context.Context, client *carbide.Client, siteId string,
) (result *carbide.InstanceType, err error) {
	// Get the list of instance types for the site:
	var instanceTypes []carbide.InstanceType
	err = client.Get().
		SetEndpoint("instance", "type").
		SetOutput(&instanceTypes).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get list of instance types: %w", err)
		return
	}

	// Check if the expected instance type already exists:
	for _, instanceType := range instanceTypes {
		r.logger.InfoContext(
			ctx,
			"Found instance type",
			slog.String("id", instanceType.Id),
			slog.String("name", instanceType.Name),
		)
		if instanceType.Name == carbideSyncInstanceTypeName {
			r.logger.InfoContext(
				ctx,
				"Instance type already exists",
				slog.String("id", instanceType.Id),
				slog.String("name", instanceType.Name),
			)
			result = &instanceType
			return
		}
	}

	// The instance type doesn't exist, create it:
	r.logger.InfoContext(
		ctx,
		"Instance type doesn't exist, creating it",
		slog.String("name", carbideSyncInstanceTypeName),
	)

	if r.flow == flowSSA {
		return nil, fmt.Errorf("instance type not found: %s", carbideSyncInstanceTypeName)
	}

	var created carbide.InstanceType
	err = client.Post().
		SetEndpoint("instance", "type").
		SetInput(&carbide.InstanceType{
			Name:   carbideSyncInstanceTypeName,
			SiteId: siteId,
		}).
		SetOutput(&created).
		Send(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance type: %w", err)
	}
	r.logger.InfoContext(
		ctx,
		"Created instance type",
		slog.String("id", created.Id),
		slog.String("name", created.Name),
	)
	return &created, nil
}

// ensureAllocation ensures that an allocation exists for the tenant at the given site. It creates the instance type,
// associates machines with it, and creates the allocation if they don't already exist.
func (r *startCarbideSyncRunner) ensureAllocation(ctx context.Context, client *carbide.Client, siteId, tenantId string,
	instanceTypeId string) (result *carbide.Allocation, err error) {
	// Check if the allocation already exists:
	var allocations []carbide.Allocation
	err = client.Get().
		SetEndpoint("allocation").
		SetQueryParameter("siteId", siteId).
		SetQueryParameter("tenantId", tenantId).
		SetOutput(&allocations).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get list of allocations: %w", err)
		return
	}
	for _, allocation := range allocations {
		r.logger.InfoContext(
			ctx,
			"Found allocation",
			slog.String("id", allocation.Id),
			slog.String("name", allocation.Name),
		)
		if allocation.Name == carbideSyncAllocationName {
			result = &allocation
			return
		}
	}

	// Create the allocation:
	r.logger.InfoContext(
		ctx,
		"Allocation not found",
	)

	if r.flow == flowSSA {
		return nil, fmt.Errorf("allocation not found: %s", carbideSyncAllocationName)
	}

	// Create the allocation:
	r.logger.InfoContext(
		ctx,
		"Creating allocation for the tenant at the site",
	)
	var allocation carbide.Allocation
	err = client.Post().
		SetEndpoint("allocation").
		SetInput(&carbide.Allocation{
			Name:     carbideSyncAllocationName,
			TenantId: tenantId,
			SiteId:   siteId,
			AllocationConstraints: []carbide.AllocationConstraint{
				{
					ResourceType:    "InstanceType",
					ResourceTypeId:  instanceTypeId,
					ConstraintType:  "Reserved",
					ConstraintValue: 1,
				},
			},
		}).
		SetOutput(&allocation).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to create allocation: %w", err)
		return
	}
	r.logger.InfoContext(
		ctx,
		"Created allocation",
		slog.String("id", allocation.Id),
		slog.String("name", allocation.Name),
	)

	// Return the allocation:
	result = &allocation
	return
}

// ensureProviderIpBlock checks if a provider IP block with the expected name exists for the site and creates it if
// it doesn't. It uses the provider client because IP block operations require the `FORGE_PROVIDER_ADMIN` role.
func (r *startCarbideSyncRunner) ensureIpBlock(
	ctx context.Context, client *carbide.Client, siteId, tenantId string) (result *carbide.IpBlock, err error) {
	// Get the list of IP blocks for the site:
	var ipBlocks []carbide.IpBlock
	err = client.Get().
		SetEndpoint("ipblock").
		SetQueryParameter("siteId", siteId).
		SetQueryParameter("tenantId", tenantId).
		SetOutput(&ipBlocks).
		Send(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get list of IP blocks: %w", err)
	}

	// Check if the expected IP block already exists:
	for i, b := range ipBlocks {
		r.logger.InfoContext(
			ctx,
			"Found IP block",
			slog.String("id", b.Id),
			slog.String("name", b.Name),
		)
		if b.Name == carbideSyncIpBlockName {
			r.logger.InfoContext(
				ctx,
				"Provider IP block already exists",
				slog.String("id", b.Id),
			)
			return &ipBlocks[i], nil
		}
	}

	if r.flow == flowSSA {
		return nil, fmt.Errorf("ipBlock not found: %s", carbideSyncIpBlockName)
	}

	// The IP block doesn't exist, create it:
	r.logger.InfoContext(
		ctx,
		"IP block doesn't exist, creating it",
	)
	var created carbide.IpBlock
	err = r.providerClient.Post().
		SetEndpoint("ipblock").
		SetInput(&carbide.IpBlock{
			Name:            carbideSyncIpBlockName,
			SiteId:          siteId,
			RoutingType:     "DatacenterOnly",
			Prefix:          "10.0.0.0",
			PrefixLength:    16,
			ProtocolVersion: "IPv4",
		}).
		SetOutput(&created).
		Send(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider IP block: %w", err)
	}
	r.logger.InfoContext(
		ctx,
		"Created provider IP block",
		slog.String("id", created.Id),
	)
	return &created, nil
}

// ensureIpBlockAllocation checks if an IP block allocation exists and creates it if it doesn't. The allocation
// derives a tenant IP block from the provider IP block. It returns the derived tenant IP block.
func (r *startCarbideSyncRunner) ensureIpBlockAllocation(
	ctx context.Context, client *carbide.Client, siteId, tenantId, ipBlockId string) (result *carbide.IpBlock, err error) {
	// Check if the IP block allocation already exists:
	var allocations []carbide.Allocation
	err = client.Get().
		SetEndpoint("allocation").
		SetQueryParameter("siteId", siteId).
		SetQueryParameter("tenantId", tenantId).
		SetOutput(&allocations).
		Send(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get list of allocations: %w", err)
	}
	var allocation *carbide.Allocation
	for i, a := range allocations {
		if a.Name == carbideSyncIpBlockAllocationName {
			allocation = &allocations[i]
			r.logger.InfoContext(
				ctx,
				"IP block allocation already exists",
				slog.String("id", a.Id),
			)
		}
	}
	if allocation == nil {
		if r.flow == flowSSA {
			return nil, fmt.Errorf("ip block allocation not found: %s", carbideSyncIpBlockAllocationName)
		}

		r.logger.InfoContext(
			ctx,
			"Creating IP block allocation for the tenant",
		)
		var created carbide.Allocation
		err = client.Post().
			SetEndpoint("allocation").
			SetInput(&carbide.Allocation{
				Name:     carbideSyncIpBlockAllocationName,
				TenantId: tenantId,
				SiteId:   siteId,
				AllocationConstraints: []carbide.AllocationConstraint{
					{
						ResourceType:    "IPBlock",
						ResourceTypeId:  ipBlockId,
						ConstraintType:  "Reserved",
						ConstraintValue: 24,
					},
				},
			}).
			SetOutput(&created).
			Send(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create IP block allocation: %w", err)
		}
		allocation = &created
	}

	// Get the derived tenant IP block ID from the allocation constraint:
	if len(allocation.AllocationConstraints) == 0 || allocation.AllocationConstraints[0].DerivedResourceId == nil {
		return nil, fmt.Errorf("allocation did not return a derived IP block ID")
	}
	derivedId := *allocation.AllocationConstraints[0].DerivedResourceId
	r.logger.InfoContext(
		ctx,
		"Using derived tenant IP block",
		slog.String("id", derivedId),
	)

	// Fetch the derived tenant IP block:
	var tenantIpBlock carbide.IpBlock
	err = client.Get().
		SetEndpoint("ipblock", derivedId).
		SetOutput(&tenantIpBlock).
		Send(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant IP block: %w", err)
	}
	return &tenantIpBlock, nil
}

// ensureInstance checks if an instance with the expected name exists and creates it if it doesn't. It waits for the
// instance to reach `Ready` status before returning.
func (r *startCarbideSyncRunner) ensureInstance(
	ctx context.Context, tenantId, instanceTypeId, networkID string, vpc *carbide.Vpc,
) (result carbide.Instance, err error) {
	// Get the list of instances:
	var instances []carbide.Instance
	err = r.tenantClient.Get().
		SetEndpoint("instance").
		SetOutput(&instances).
		Send(ctx)
	if err != nil {
		return result, fmt.Errorf("failed to get list of instances: %w", err)
	}

	// Check if the expected instance already exists:
	var found bool
	for _, inst := range instances {
		r.logger.InfoContext(
			ctx,
			"Found instance",
			slog.String("id", inst.Id),
			slog.String("name", inst.Name),
			slog.String("status", inst.Status),
		)
		if inst.Name == carbideSyncInstanceName {
			result = inst
			found = true
		}
	}

	// Create the instance if it doesn't exist:
	if !found {
		ipxeScript, err := r.makeIpxeScript(ctx, carbideSyncIpxeScriptURL)
		if err != nil {
			return result, fmt.Errorf("failed to make iPXE script: %w", err)
		}
		r.logger.InfoContext(
			ctx,
			"Instance doesn't exist, creating it",
			slog.String("name", carbideSyncInstanceName),
		)
		var instanceInterfaces []carbide.InstanceInterface
		if vpc.NetworkVirtualizationType != "FNN" {
			instanceInterfaces = []carbide.InstanceInterface{
				{
					SubnetId:   networkID,
					IsPhysical: true,
				},
			}
		} else {
			instanceInterfaces = []carbide.InstanceInterface{
				{
					VPCPrefixId: networkID,
					IsPhysical:  true,
				},
			}
		}
		err = r.tenantClient.Post().
			SetEndpoint("instance").
			SetInput(&carbide.Instance{
				Name:           carbideSyncInstanceName,
				InstanceTypeId: instanceTypeId,
				TenantId:       tenantId,
				VpcId:          vpc.Id,
				IpxeScript:     ipxeScript,
				Interfaces:     instanceInterfaces,
				SshKeyGroupIds: []string{carbideSyncSshKeyGroupId},
			}).
			SetOutput(&result).
			Send(ctx)
		if err != nil {
			return result, fmt.Errorf("failed to create instance: %w", err)
		}
		r.logger.InfoContext(
			ctx,
			"Created instance",
			slog.String("id", result.Id),
			slog.String("name", result.Name),
			slog.String("status", result.Status),
		)
	} else {
		r.logger.InfoContext(
			ctx,
			"Instance already exists",
			slog.String("id", result.Id),
			slog.String("name", result.Name),
			slog.String("status", result.Status),
		)
	}

	// Wait for the instance to be ready:
	if result.Status != "Ready" {
		result, err = r.waitForInstanceReady(ctx, result.Id)
		if err != nil {
			return result, fmt.Errorf("failed waiting for instance to be ready: %w", err)
		}
	}

	return result, nil
}

// ensureNetworkResource ensures the appropriate network resource exists based on VPC type.
// For FNN VPCs, it creates a VPC prefix; for others, it creates a subnet.
// Returns the network resource ID to be used when creating instances.
func (r *startCarbideSyncRunner) ensureNetworkResource(ctx context.Context, vpc *carbide.Vpc, ipBlockId string) (string, error) {
	if vpc.NetworkVirtualizationType == "FNN" {
		vpcPrefix, err := r.ensureVPCPrefix(ctx, vpc.Id, ipBlockId)
		if err != nil {
			return "", fmt.Errorf("failed to ensure VPC prefix exists: %w", err)
		}
		return vpcPrefix.Id, nil
	}

	subnet, err := r.ensureSubnet(ctx, vpc.Id, ipBlockId)
	if err != nil {
		return "", fmt.Errorf("failed to ensure subnet exists: %w", err)
	}
	return subnet.Id, nil
}

// ensureSubnet checks if a subnet with the expected name exists in the VPC and creates it if it doesn't.
func (r *startCarbideSyncRunner) ensureSubnet(ctx context.Context, vpcId, ipBlockId string) (result *carbide.Subnet,
	err error) {
	// Get the list of subnets for the VPC:
	var subnets []carbide.Subnet
	err = r.tenantClient.Get().
		SetEndpoint("subnet").
		SetQueryParameter("vpcId", vpcId).
		SetOutput(&subnets).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get list of subnets: %w", err)
		return
	}

	// Check if the expected subnet already exists:
	for _, subnet := range subnets {
		r.logger.InfoContext(
			ctx,
			"Found subnet",
			slog.String("id", subnet.Id),
			slog.String("name", subnet.Name),
		)
		if subnet.Name == carbideSyncSubnetName {
			r.logger.InfoContext(
				ctx,
				"Subnet already exists",
				slog.String("id", subnet.Id),
			)
			result = &subnet
			return
		}
	}

	// The subnet doesn't exist, create it:
	r.logger.InfoContext(
		ctx,
		"Subnet doesn't exist, creating it",
		slog.String("name", carbideSyncSubnetName),
	)
	var subnet carbide.Subnet
	err = r.tenantClient.Post().
		SetEndpoint("subnet").
		SetInput(&carbide.Subnet{
			Name:         carbideSyncSubnetName,
			VpcId:        vpcId,
			Ipv4BlockId:  ipBlockId,
			PrefixLength: 26,
		}).
		SetOutput(&subnet).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to create subnet: %w", err)
		return
	}
	r.logger.InfoContext(
		ctx,
		"Created subnet",
		slog.String("id", subnet.Id),
		slog.String("name", subnet.Name),
	)

	// Wait till the sunet is ready:
	interval := 10 * time.Second
	for {
		err = r.tenantClient.Get().
			SetEndpoint("subnet", subnet.Id).
			SetOutput(&subnet).
			Send(ctx)
		if err != nil {
			err = fmt.Errorf("failed to get subnet: %w", err)
			return
		}
		if subnet.Status == "Ready" {
			r.logger.InfoContext(
				ctx,
				"Subnet is ready",
				slog.String("id", subnet.Id),
			)
			result = &subnet
			return
		}
		r.logger.InfoContext(
			ctx,
			"Subnet is not ready yet, waiting",
			slog.String("id", subnet.Id),
			slog.String("status", subnet.Status),
			slog.Duration("interval", interval),
		)
		select {
		case <-ctx.Done():
			err = fmt.Errorf("context cancelled while waiting for subnet to be ready: %w", ctx.Err())
			return
		case <-time.After(interval):
		}
	}
}

func (r *startCarbideSyncRunner) ensureVPCPrefix(ctx context.Context, vpcId, ipBlockId string) (result *carbide.VPCPrefix,
	err error) {
	// Get the list of subnets for the VPC:
	var vpcPrefixes []carbide.VPCPrefix
	err = r.tenantClient.Get().
		SetEndpoint("vpc-prefix").
		SetQueryParameter("vpcId", vpcId).
		SetOutput(&vpcPrefixes).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get list of vpc prefixes: %w", err)
		return
	}

	// Check if the expected vpc prefix already exists:
	for _, vpcPrefix := range vpcPrefixes {
		r.logger.InfoContext(
			ctx,
			"Found vpc prefix",
			slog.String("id", vpcPrefix.Id),
			slog.String("name", vpcPrefix.Name),
		)
		if vpcPrefix.Name == carbideSyncVPCPrefixName {
			r.logger.InfoContext(
				ctx,
				"VPC prefix already exists",
				slog.String("id", vpcPrefix.Id),
			)
			result = &vpcPrefix
			return
		}
	}

	// The vpc prefix doesn't exist, create it:
	r.logger.InfoContext(
		ctx,
		"VPC prefix doesn't exist, creating it",
		slog.String("name", carbideSyncVPCPrefixName),
	)

	err = r.tenantClient.Post().
		SetEndpoint("vpc-prefix").
		SetInput(&carbide.VPCPrefix{
			Name:      carbideSyncVPCPrefixName,
			VpcId:     vpcId,
			Prefix:    "7.243.43.192/28",
			IPBlockId: ipBlockId,
		}).
		SetOutput(&result).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to create vpc prefix: %w", err)
		return
	}
	r.logger.InfoContext(
		ctx,
		"Created vpc prefix",
		slog.String("id", result.Id),
		slog.String("name", result.Name),
	)

	return
}

// ensureVpc checks if a VPC with the expected name exists for the given site and creates it if it doesn't.
func (r *startCarbideSyncRunner) ensureVpc(ctx context.Context, siteId string) (result *carbide.Vpc, err error) {
	// Get the list of VPCs for the site:
	var vpcs []carbide.Vpc
	err = r.tenantClient.Get().
		SetEndpoint("vpc").
		SetQueryParameter("siteId", siteId).
		SetOutput(&vpcs).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get list of VPCs: %w", err)
		return
	}

	// Check if the expected VPC already exists:
	for _, vpc := range vpcs {
		r.logger.InfoContext(
			ctx,
			"Found VPC",
			slog.String("id", vpc.Id),
			slog.String("name", vpc.Name),
		)
		if vpc.Name == carbideSyncVpcName {
			r.logger.InfoContext(
				ctx,
				"VPC already exists",
				slog.String("id", vpc.Id),
				slog.String("name", vpc.Name),
			)
			result = &vpc
			return
		}
	}

	// The VPC doesn't exist, create it:
	r.logger.InfoContext(
		ctx,
		"VPC doesn't exist, creating it",
		slog.String("name", carbideSyncVpcName),
		slog.String("site_id", siteId),
	)
	var vpc carbide.Vpc
	err = r.tenantClient.Post().
		SetEndpoint("vpc").
		SetInput(&carbide.Vpc{
			Name:   carbideSyncVpcName,
			SiteId: siteId,
		}).
		SetOutput(&vpc).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to create VPC: %w", err)
		return
	}
	r.logger.InfoContext(
		ctx,
		"Created VPC",
		slog.String("id", vpc.Id),
		slog.String("name", vpc.Name),
	)

	// Return the created VPC:
	result = &vpc
	return
}

// findSite searches for the expected site by name and returns it. It returns an error if the site doesn't exist.
func (r *startCarbideSyncRunner) findSite(ctx context.Context) (result *carbide.Site, err error) {
	// Get the list of sites:
	var sites []carbide.Site
	err = r.providerClient.Get().
		SetEndpoint("site").
		SetOutput(&sites).
		Send(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get list of sites: %w", err)
		return
	}

	// Search for the expected site:
	for _, site := range sites {
		r.logger.InfoContext(
			ctx,
			"Found site",
			slog.String("id", site.Id),
			slog.String("name", site.Name),
		)
		if site.Name == carbideSyncSiteName {
			result = &site
			return
		}
	}

	err = fmt.Errorf("site '%s' not found", carbideSyncSiteName)
	return
}

// waitForInstanceReady polls the instance until its status becomes `Ready` or the context is cancelled.
func (r *startCarbideSyncRunner) waitForInstanceReady(
	ctx context.Context, instanceId string) (result carbide.Instance, err error) {
	interval := 10 * time.Second
	for {
		err = r.tenantClient.Get().
			SetEndpoint(fmt.Sprintf("instance/%s", instanceId)).
			SetOutput(&result).
			Send(ctx)
		if err != nil {
			return result, fmt.Errorf("failed to get instance: %w", err)
		}
		if result.Status == "Ready" {
			r.logger.InfoContext(
				ctx,
				"Instance is ready",
				slog.String("id", result.Id),
			)
			return result, nil
		}
		r.logger.InfoContext(
			ctx,
			"Instance is not ready yet, waiting",
			slog.String("id", result.Id),
			slog.String("status", result.Status),
			slog.Duration("interval", interval),
		)
		select {
		case <-ctx.Done():
			return result, fmt.Errorf(
				"context cancelled while waiting for instance to be ready: %w", ctx.Err(),
			)
		case <-time.After(interval):
		}
	}
}

// makeIpxeScript generates the iPXE script that will be used to boot instances. It downloads the kernel and initrd
// from the assisted image service.
func (r *startCarbideSyncRunner) makeIpxeScript(ctx context.Context, ipxeScriptURL string) (result string, err error) {
	if _, err := url.Parse(ipxeScriptURL); err != nil {
		return "", fmt.Errorf("failed to parse ipxe script URL: %w", err)
	}

	resp, err := http.Get(ipxeScriptURL)
	if err != nil {
		return "", fmt.Errorf("failed to get ipxe script: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read ipxe script: %w", err)
	}

	return string(body), nil
}

// createClient creates a Carbide API client for the given user. It creates a token store and token source internally,
// using the shared CA pool and common OAuth configuration.
func (r *startCarbideSyncRunner) createClient(ctx context.Context, username, password string) (result *carbide.Client, err error) {
	r.logger.InfoContext(
		context.Background(),
		"Creating Carbide API client",
		slog.String("username", username),
	)

	// Create the token store:
	store, err := auth.NewMemoryTokenStore().
		SetLogger(r.logger).
		Build()
	if err != nil {
		err = fmt.Errorf("failed to create token store: %w", err)
		return
	}

	// Create the token source:
	tokenSource, err := oauth.NewTokenSource().
		SetLogger(r.logger).
		SetStore(store).
		SetCaPool(r.caPool).
		SetIssuer("http://localhost:8080/realms/carbide-dev").
		SetFlow(oauth.PasswordFlow).
		SetClientId("carbide-api").
		SetClientSecret("carbide-local-secret").
		SetUsername(username).
		SetPassword(password).
		Build()
	if err != nil {
		err = fmt.Errorf("failed to create token source: %w", err)
		return
	}

	// The organization is determined by the presence of the '<org>:FORGE_<role>' values inside the 'realm_access.roles' claim.
	token, err := tokenSource.Token(ctx)
	if err != nil {
		err = fmt.Errorf("failed to get token: %w", err)
		return
	}
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err = parser.ParseUnverified(token.Access, claims)
	if err != nil {
		err = fmt.Errorf("failed to parse token: %w", err)
		return
	}
	r.logger.InfoContext(
		ctx,
		"Token claims",
		slog.Any("claims", claims),
	)
	var roles []string
	err = r.jqTool.Evaluate(`.realm_access.roles[]`, claims, &roles)
	if err != nil {
		err = fmt.Errorf("failed to get roles from token: %w", err)
		return
	}
	var orgIds []string
	for _, orgRole := range roles {
		orgId, role, ok := strings.Cut(orgRole, ":")
		if !ok {
			continue
		}
		if strings.HasPrefix(role, "FORGE_") && !slices.Contains(orgIds, orgId) {
			orgIds = append(orgIds, orgId)
		}
	}
	if len(orgIds) == 0 {
		err = errors.New("no organizations found in token")
		return
	}
	sort.Strings(orgIds)
	orgId := orgIds[0]
	if len(orgIds) > 1 {
		r.logger.WarnContext(
			ctx,
			"Multiple organizations found in token",
			slog.Any("candidates", orgIds),
			slog.String("selected", orgId),
		)
	}

	// Calculate the user agent:
	userAgent := fmt.Sprintf("%s/%s", carbideSyncUserAgent, version.Get())

	// Create the client:
	result, err = carbide.NewClient().
		SetLogger(r.logger).
		SetCaPool(r.caPool).
		SetUserAgent(userAgent).
		SetUrl("http://localhost:8388/v2").
		SetOrg(orgId).
		SetTokenSource(tokenSource).
		Build()
	if err != nil {
		err = fmt.Errorf("failed to create client: %w", err)
		return
	}

	return
}

// loadTenantCredentialsFromSecret loads tenant credentials from a Kubernetes secret.
// The secret is configured via environment variables:
//   - TENANT_SECRET_NAME: Name of the secret (default: "tenant-credentials")
//   - TENANT_SECRET_NAMESPACE: Namespace of the secret (default: pod's namespace)
//
// The secret should contain the following keys:
//   - client-id: The OAuth client ID for the tenant
//   - client-secret: The OAuth client secret for the tenant
//   - org-id: The organization ID for the tenant
//   - scopes: The OAuth scopes for the tenant
func (r *startCarbideSyncRunner) loadTenantCredentialsFromSecret(ctx context.Context) error {
	// Get secret name from environment variable (with default)
	secretName := os.Getenv(tenantSecretNameEnv)
	if secretName == "" {
		secretName = tenantSecretNameDefault
	}

	// Determine the namespace to use
	namespace := os.Getenv(tenantSecretNamespaceEnv)
	if namespace == "" {
		// Try to read the namespace from the pod's service account
		data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return fmt.Errorf("failed to determine namespace (set %s or run in-cluster): %w",
				tenantSecretNamespaceEnv, err)
		}
		namespace = strings.TrimSpace(string(data))
	}

	// Get the secret from the cluster
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: namespace,
		Name:      secretName,
	}
	err := r.kubeClient.Get(ctx, secretKey, secret)
	if err != nil {
		return fmt.Errorf("failed to get tenant credentials secret '%s/%s': %w",
			namespace, secretName, err)
	}

	// Extract credentials from the secret
	clientId, ok := secret.Data["client-id"]
	if !ok || len(clientId) == 0 {
		return fmt.Errorf("tenant credentials secret '%s/%s' is missing 'client-id' key",
			namespace, secretName)
	}
	r.tenantClientId = strings.TrimSpace(string(clientId))

	clientSecret, ok := secret.Data["client-secret"]
	if !ok || len(clientSecret) == 0 {
		return fmt.Errorf("tenant credentials secret '%s/%s' is missing 'client-secret' key",
			namespace, secretName)
	}
	r.tenantClientSecret = strings.TrimSpace(string(clientSecret))

	// Organization ID is required in the secret
	orgId, ok := secret.Data["org-id"]
	if !ok || len(orgId) == 0 {
		return fmt.Errorf("tenant credentials secret '%s/%s' is missing 'org-id' key",
			namespace, secretName)
	}
	r.tenantOrgId = strings.TrimSpace(string(orgId))

	scopes, ok := secret.Data["scopes"]
	if !ok || len(scopes) == 0 {
		return fmt.Errorf("tenant credentials secret '%s/%s' is missing 'scopes' key",
			namespace, secretName)
	}
	r.tenantScopes = strings.TrimSpace(string(scopes))

	r.logger.InfoContext(ctx, "Loaded tenant credentials from Kubernetes secret",
		slog.String("namespace", namespace),
		slog.String("secret_name", secretName),
	)

	return nil
}

// createTenantClient creates a Carbide API client using tenant credentials from the Kubernetes secret.
// This client is used to perform operations on behalf of the tenant/customer.
func (r *startCarbideSyncRunner) createTenantClient(ctx context.Context) (result *carbide.Client, err error) {
	r.logger.InfoContext(
		ctx,
		"Creating Carbide API tenant client (credentials from Kubernetes secret)",
	)

	// Validate that tenant credentials were loaded from the secret
	if r.tenantClientId == "" || r.tenantClientSecret == "" {
		err = errors.New("tenant credentials not loaded: ensure secret exists with 'client-id' and 'client-secret' keys")
		return
	}

	// Create the token source using tenant's credentials
	tokenURL := strings.TrimSuffix(r.args.issuer, "/") + "/token"
	tokenSource, err := NewBasicAuthTokenSource().
		SetLogger(r.logger).
		SetTokenURL(tokenURL).
		SetClientId(r.tenantClientId).
		SetClientSecret(r.tenantClientSecret).
		SetScopes(r.tenantScopes).
		Build()
	if err != nil {
		err = fmt.Errorf("failed to create tenant token source: %w", err)
		return
	}

	r.logger.InfoContext(
		ctx,
		"Using tenant organization ID",
		slog.String("org_id", r.tenantOrgId),
	)

	// Calculate the user agent
	userAgent := fmt.Sprintf("%s/%s", carbideSyncUserAgent, version.Get())

	// Create the tenant client
	result, err = carbide.NewClient().
		SetLogger(r.logger).
		SetUserAgent(userAgent).
		SetUrl(r.args.endpoint).
		SetOrg(r.tenantOrgId).
		SetTokenSource(tokenSource).
		Build()
	if err != nil {
		err = fmt.Errorf("failed to create tenant client: %w", err)
		return
	}

	return
}

// Environment variable for flow configuration
const (
	// flowEnv is the environment variable for the operation flow.
	flowEnv = "CARBIDE_FLOW"
	// flowSSA indicates SSA mode (read-only, resources must pre-exist).
	flowSSA = "SSA"
)

// Environment variables for tenant secret configuration
const (
	// tenantSecretNameEnv is the environment variable for the tenant credentials secret name.
	tenantSecretNameEnv = "TENANT_SECRET_NAME"
	// tenantSecretNamespaceEnv is the environment variable for the tenant credentials secret namespace.
	tenantSecretNamespaceEnv = "TENANT_SECRET_NAMESPACE"
	// tenantSecretNameDefault is the default name for the tenant credentials secret.
	tenantSecretNameDefault = "tenant-credentials"
)

// carbideSyncUserAgent is the user agent string for the carbide sync.
const carbideSyncUserAgent = "fulfillment-carbide-sync"

// carbideSyncSiteName is the name of the site that the carbide sync will use.
const carbideSyncSiteName = "local-dev-site"

// carbideSyncVpcName is the name of the VPC that the carbide sync will use.
const carbideSyncVpcName = "my-vpc"

// carbideSyncIpBlockName is the name of the IP block that the carbide sync will use.
const carbideSyncIpBlockName = "my-ipblock"

// carbideSyncIpBlockAllocationName is the name of the IP block allocation.
const carbideSyncIpBlockAllocationName = "my-ipblock-allocation"

// carbideSyncSubnetName is the name of the subnet that the carbide sync will use.
const carbideSyncSubnetName = "my-subnet"

// carbideSyncInstanceTypeName is the name of the instance type that the carbide sync will create.
const carbideSyncInstanceTypeName = "my-instance-type"

// carbideSyncAllocationName is the name of the allocation that the carbide sync will create.
const carbideSyncAllocationName = "my-allocation"

// carbideSyncInstanceName is the name of the instance that the carbide sync will create.
const carbideSyncInstanceName = "my-instance"

// carbideSyncVPCPrefixName is the name of the VPC prefix that the carbide sync will use.
const carbideSyncVPCPrefixName = "my-vpc-prefix"

// carbideSyncSshKeyGroupId is the ID of the SSH key group that the carbide sync will use.
const carbideSyncSshKeyGroupId = "my-ssh-key-group"

// carbideSyncIpxeScriptURL is the URL of the iPXE script that the carbide sync will use.
const carbideSyncIpxeScriptURL = "http://assisted-image-service/mykernel"
