---
Authors: Maxim Dietz (maxim.dietz@goteleport.com)
State: draft
---

# RFD 230 - Component Feature Advertisement

## Required Approvers

- Engineering: (@r0mant && @rosstimothy)

## Related

- [RFD 228](https://github.com/gravitational/teleport/blob/master/rfd/0228-resource-scoped-constraints-in-access-requests.md) - Resource-Scoped Constraints in Access Requests
- [RFD 225](https://github.com/gravitational/teleport/blob/master/rfd/0225-teleport-extended-support.md) - Teleport Extended Release Support

## What

This RFD introduces a small feature advertisement payload carried on the presence resources that services already
heartbeat to Auth (e.g., `ServerV2` for SSH, `AppServerV3` for app access, and the corresponding types for
database and Kubernetes access).

Auth persists these advertised features alongside the existing presence resources and exposes them through its existing
APIs. Consumers such as Proxy can read these feature sets and intersect them across a request path to
decide whether to enable behavior that depends on a given capability.

The initial application is for App Service and Auth to signal support for Resource Constraints in certificates
([RFD 228](https://github.com/gravitational/teleport/blob/master/rfd/0228-resource-scoped-constraints-in-access-requests.md)),
so that Web can hide Resource Constraint–dependent flows when the required support is not present.

### Terminology

In this RFD:

- **Service** means a Teleport agent/service that reports its presence to Auth, such as App Service, SSH/Node Service,
  Database Service, or Kubernetes Service. These are the processes that advertise their feature support via presence
  resources and heartbeats.
- **Consumer** means a process that reads feature support and derives higher-level behavior from it, such as
  Proxy/Web UI and Auth.
- **Agentless resource** means a resource that carries no `ComponentFeatures` of its own, because no serving agent
  advertises for it over the inventory control stream. That happens either because it has no serving agent (an
  integration-backed app, an OpenSSH node) or because its serving agent reaches Auth only through the authorized API (a
  Windows desktop). Its complement, an **agent-served** resource, carries its serving agent's advertisement, set over the
  inventory stream. The same kind can appear either way.

Auth plays both roles:

- As a service, it exposes its own `ComponentFeatures` via its heartbeat.
- As a consumer, it stores and serves the feature sets advertised by other services, using them internally and
  surfacing them to other consumers.

> [!IMPORTANT]
> This mechanism is intended as a non-security signaling layer, with its initial use being UX/API gating and
> coordination between services and consumers to ensure backwards/forwards compatibility with changes required for
> [RFD 228](https://github.com/gravitational/teleport/blob/master/rfd/0228-resource-scoped-constraints-in-access-requests.md).
> It does not replace secure design or fail-closed behavior. All security-relevant behavior MUST remain correct in the
> absence of flags and MUST fail closed. Treat flags as hints for conditional UX or workflows, not as authorization
> signals.

## Why

Relying solely on version numbers to determine feature support is fragile, especially in a distributed system with
multiple services that can be upgraded independently and where certain features may be backported to older versions.

Blindly showing UI elements for features that backing services do not support leads to a frustrating user
experience, even if errors are handled gracefully. This mechanism provides an explicit, composable signal consumers can
use to "fail silently" when certain capabilities are not available and hide unsupported flows from the get-go.

## Design

### Payload format

The payload is simple and forward-compatible by design. In v1, features are Boolean: presence means "supported", absence
means "not supported". Each feature is identified by an append-only enum value so IDs remain stable over time.

```protobuf
enum ComponentFeatureID {
  COMPONENT_FEATURE_ID_UNSPECIFIED             = 0;
  // v1 addition: Support for RFD 228 ResourceAccessIDs and Resource Constraints
  COMPONENT_FEATURE_ID_RESOURCE_CONSTRAINTS_V1 = 1;
}

message ComponentFeatures {
  repeated ComponentFeatureID features = 1;
}
```

Unknown feature IDs can be ignored by consumers (optionally logged once per service identity). Because senders only
include "true" values, the payloads stay compact, and omission naturally encodes "false"/"not supported".

### Advertising from services

A feature works for a resource only if every component serving it was built with it. `ComponentFeatures` is how each
component advertises what its own build supports, so consumers intersect those advertisements along the serving path
rather than infer support from version numbers, and a component built without a feature simply never advertises it.

How a resource contributes its own part of that intersection depends on whether it is agent-served or agentless, which
[Agentless resources](#agentless-resources) covers in full. Either way the resource's part is intersected with the
advertisements of the other components serving it (Proxy and Auth), so a feature counts as supported only if everything
in the path does.

Each service that advertises features exposes a list of its current `ComponentFeatures`. For heartbeat-ing services,
this payload is attached to the presence resources they already send over the inventory control stream (e.g.,
`AppServerSpecV3` for App Service). No changes are required in the heartbeat
machinery itself; services simply add a `ComponentFeatures` field to the Spec of the presence resources they are
already constructing.

For resources that heartbeat over the inventory control stream, the value lives on the resource rather than on the
service's own record. A single app can be served by several `app_service`s at once, and its support is whatever all of
them share; carrying the value on each `AppServer` lets the per-app aggregation the unified-resource cache already
performs intersect them for free, and lets a consumer ask one resource whether a flow is supported end to end. Reporting
per service instead would push that correlation, which service serves which resource, onto every consumer.

The field is server-managed, and the inventory stream is what makes that safe. An agent's heartbeat reaches `auth.Server`
directly, so the advertisement it sets is trusted; the authorized resource APIs
(`ServerWithRoles.UpsertApplicationServer`, `UpsertNode`) must nil the field, so nothing that reaches presence through the
API can claim support it doesn't have. That stripping is the trust boundary the rest of the design leans on, and it is
not yet in place, so it is required follow-up. A resource established through the API rather than the inventory stream
carries no advertisement, which is the agentless case [Agentless resources](#agentless-resources) handles.

A service should advertise a flag only when:

- the implementation is present in the build, and
- it is usable with the current configuration and dependencies.

For the initial Resource Constraints work, support is not configuration-dependent: a build either implements the flow or
it does not. A service must advertise the flag only once its build can honor the flow end to end, not merely once the
field exists. The field shipped one release ahead of enforcement, so builds in that window advertised support they could
not honor; consumers version-gate those out as a transitional measure until they age past support.

Auth stores these payloads alongside existing status information so they are available through the same APIs that
already expose presence and cluster state.

Auth itself won't carry `ComponentFeatures` on an auth-server presence resource. Instead, it can expose its own feature
support via adding some `AuthComponentFeatures` field to its Spec when heartbeating.

### Agentless resources

The same kind can be agent-served in one cluster and agentless in another. An `AppServer` with an integration set is
agentless and served by Proxy directly; one served by an `app_service` is agent-served. An agentless resource reaches
presence through the authorized API rather than the inventory stream (see
[Advertising from services](#advertising-from-services)), so it carries no trustworthy advertisement and its
`ComponentFeatures` is empty.

The two cases are read differently. An agent-served resource is left alone: its advertisement is read as-is, so an older
agent that never advertised a feature reads as not supporting it and the mixed-version case keeps working. An agentless
resource has no advertisement to read, so its eligibility is derived from its type (which says only whether the kind is
eligible) and then intersected with the advertisements of the components serving it (the serving service where there is
one, plus Proxy and Auth).

`GetEffectiveServerFeatures` implements that split. It derives from type for the agentless patterns it knows about and
otherwise reads the agent's advertisement, stripping any feature an agent advertised before its build could honor it (the
version gate from [Advertising from services](#advertising-from-services)):

```go
func GetEffectiveServerFeatures(component versionedComponent) *componentfeaturesv1.ComponentFeatures {
    // Agentless app (integration-served): derive eligibility from the app type.
    if appServer, ok := component.(types.AppServer); ok && appServer.GetApp().GetIntegration() != "" {
        return ForAppServer(appServer)
    }
    // Agentless SSH node (OpenSSH/EICE): derive eligibility from the node type.
    if node, ok := component.(types.Server); ok && node.IsOpenSSHNode() {
        return ForSSHServer()
    }
    // Agent-served: read the agent's advertisement, dropping any feature it
    // claimed before its build could honor the flow end to end.
    features := component.GetComponentFeatures()
    if version, err := semver.NewVersion(component.GetTeleportVersion()); err == nil &&
        version.LessThan(minResourceConstraintsVersion) {
        return withoutFeature(features, FeatureResourceConstraintsV1)
    }
    return features
}
```

This derivation runs where resources are read out, at Auth's unified-resource cache and Proxy's API handler. Both run it
so the value survives mixed-version clusters: Auth fills it in, and Proxy re-derives for the case where an older Auth has
not, which is how integration-served apps were missed before. Every read path that gates on features must call it: the
Proxy SSH path still reads the stored field directly (`apiserver.go`), so OpenSSH/EICE nodes get nothing until it moves
to `GetEffectiveServerFeatures`, the same switch the app path already made.

A reader that goes straight to the stored `ComponentFeatures` bypasses this and sees nothing for an agentless resource,
and that failure is silent. A `forbidigo` rule could flag direct `GetComponentFeatures` reads outside
`lib/componentfeatures` to catch that, like other existing "use the wrapper" rules we have.

The handling per kind follows; the unified-resources switch (`lib/web/apiserver.go`) and the `GetEffectiveServerFeatures`
branches remain the source of truth for the exact set. Git servers, bare `KubeCluster` records, and
`SAMLIdPServiceProvider`s are out of scope here, with no feature consumer or no `ComponentFeatures` to carry.

#### Apps

An app is agent-served when an `app_service` proxies it and agentless when an integration serves it directly, told apart
by `GetApp().GetIntegration() != ""`. An agent-served app's `AppServer` carries the advertisement and is read as-is; an
agentless app has none, so its eligibility is derived with `ForAppServer`. Implemented.

#### SSH nodes

A Teleport node advertises `ForSSHServer()` on its own heartbeat. OpenSSH and OpenSSH-EICE nodes have no agent (discovery
registers them through `UpsertNode`) and are recognized by `IsOpenSSHNode()`; their eligibility is derived with
`ForSSHServer` at read, the same shape as apps. Drafted, pending the decision here before the PR.

#### Databases

A `database_service` always heartbeats the `DatabaseServer` wrapper over the inventory stream, and the `Database` type has
no integration field, so a database is never agentless. Support rides on the heartbeat and intersects across the servers
backing a database, reusing the per-resource aggregation apps already use. Nothing is derived at read. Planned.

#### Kubernetes

A `kube_service` heartbeats the `KubeServer` wrapper, so kube is agent-served like databases. There is no agentless form to
detect today: the persisted `KubeCluster` has no integration field, and only the discovery-time `DiscoveredEKSCluster`
wrapper exposes `GetIntegration()`. Integration-served kube access would first need that signal persisted on the resource,
mirroring apps. Planned, agent-served only.

#### Windows desktops

A `windows_desktop_service` serves Windows desktops but registers each `WindowsDesktop` through the authorized
`UpsertWindowsDesktop` API rather than the inventory stream, so the desktop never carries an advertisement of its own. Its
eligibility is derived from the desktop type and intersected with the serving service's advertisement, located through
`GetHostID()` and carried on the service's own `WindowsDesktopService` record, plus Auth and Proxy. Still open is where
the `windows_desktop_service` advertisement lives, since its own record is also written through the authorized API.
Planned.

#### Linux desktops

A `LinuxDesktop` is created through `linuxdesktopv1` and has no serving agent at all, so it too carries no advertisement.
Its eligibility is derived from the desktop type and intersected with Auth and Proxy only. Planned.

### Consuming feature information

On the consumer side, the logic is straightforward. For a target operation, the consumer gathers the participating
services (for example, Auth and the App Service that will serve an app session) and intersects their feature sets to
determine feature support.

In practice,

- Consumers obtain per-service `ComponentFeatures` by reading presence resources from Auth (e.g., app servers,
  database servers, and nodes).
- If the feature requires auth support, consumers also obtain all present Auth instances (e.g., via
  `accessPoint.GetAuthServers()` in Web handlers), which contain Auth's own `ComponentFeatures` on their Specs.
- They then compute an intersection of these sets for the path or resource in question and gate UX or other
  behavior on that intersection.

The Web UI should not need to deal with raw feature IDs directly. Proxy should evaluate the intersection logic and
derive higher-level capability bits that are exposed to consumers (such as Web UI) via existing APIs. If Proxy does not
implement this logic, these will never be set, and Web UI will behave as "feature unsupported" implicitly.

### `tctl` visibility

Each service's `ComponentFeatures` should be surfaced via `tctl inventory list` / `tctl inventory get` (e.g., as a
comma-separated `features` column and in the JSON/YAML output). This gives CLI users a simple way to confirm which
agents support a capability and to debug mixed-version rollouts.

### Scope of v1

In v1, the implementation is limited to:

- App Service advertising `ComponentFeatures` on `AppServerV3` presence records for AWS Console applications.
- Auth and Proxy exposing their own `ComponentFeatures` via their `ServerSpecV2` when heartbeating.
- Proxy/Web UI consuming these feature sets to gate Resource Constraint–dependent flows.
- Compute-at-read-time handling for agentless `AppServerV3` resources (integration-backed apps) and agentless `ServerV2`
  SSH nodes (OpenSSH/EICE) via `GetEffectiveServerFeatures`. Databases and Kubernetes advertise via their agent
  heartbeats; desktops are designed but not yet implemented (see [Agentless resources](#agentless-resources)).

The design is intentionally generic so that other services can adopt `ComponentFeatures` for future features without
changing any core model.

### Example: Resource Constraints

The initial use-case is Resource Constraints in certificates
([RFD 228](https://github.com/gravitational/teleport/blob/master/rfd/0228-resource-scoped-constraints-in-access-requests.md)):

- Auth must accept `ResourceAccessID`s carrying `ResourceConstraints` in Access Requests, embed them into and parse them
  from X.509 `tlsca`/`sshca` Identity certificates, and enforce them via `AccessChecker` when issuing AWS Console
  sessions.
- App Service does not implement any Resource Constraint logic itself at this point; it is responsible for proxying
  application traffic. However, only some resource kinds (initially, only AWS Console Application resources) should
  participate in Resource-Constraint-related flows, so App Service must advertise support accordingly.
- Web must only expose Resource Constraint-related flows when the rest of the path can honor them.

#### App Service: advertise via `AppServer` heartbeats

The App Service already uses `HeartbeatV2` to send `AppServerV3` resources for each proxied app:

```go
heartbeat, err := srv.NewAppServerHeartbeat(srv.HeartbeatV2Config[*types.AppServerV3]{
	InventoryHandle: s.c.InventoryHandle,
	GetResource: s.getServerInfoFunc(app),
	OnHeartbeat: s.c.OnHeartbeat,
})
```

`GetResource` builds the `*types.AppServerV3` that `appServerHeartbeatV2.Announce` wraps in
`InventoryHeartbeat{AppServer: ...}` and pushes over the inventory control stream.

To advertise feature support from App Service, `AppServerSpecV3` is extended with a new field carrying a list of
`ComponentFeatureID`s:

```protobuf
message AppServerSpecV3 {
  // existing fields...
  ComponentFeatures component_features = N;
}
```

For Resource Constraints, this flag is per-application, not per-process. Only AWS Console apps (initially) are
eligible for Resource Constraints. Before each heartbeat, the App Service sets `ComponentFeatures` on the `AppServerV3`
via a centralized helper that determines features from the app type:

```go
// In lib/componentfeatures/advertisement.go
func ForAppServer(g appServerInfoGetter) *componentfeaturesv1.ComponentFeatures {
    if app := g.GetApp(); !app.IsAWSConsole() {
        return New()
    }
    return New(FeatureResourceConstraintsV1)
}

// In lib/srv/app/server.go, called before each heartbeat
server.SetComponentFeatures(componentfeatures.ForAppServer(server))
```

As multiple app servers may serve a single application, the aggregation logic used in `UnifiedResourcesCache` should
be updated to intersect the `ComponentFeatures` of all `AppServerV3` records backing a given application, e.g.:

```go
// New wrappers around types.AppServer to hold aggregated features
type aggregatedAppServer struct {
	types.AppServer
	features *presence.ComponentFeatures
}
func (a *aggregatedAppServer) Copy() types.AppServer {
    out := a.AppServer.Copy()
    if a.features != nil {
        out.SetComponentFeatures(a.features)
    }
    return out
}
func (a *aggregatedAppServer) CloneResource() types.ResourceWithLabels {
    return a.Copy()
}

// Compute intersection of features across multiple app servers
func intersectComponentFeaturesApp(servers map[string]types.AppServer) *presence.ComponentFeatures { /*...*/ }

// Wire up in newResourceCollection
func newResourceCollection(r resource) resourceCollection {
    switch r := r.(type) {
    case types.AppServer:
        return newServerResourceCollection(r,
            func (latest types.AppServer, servers map[string]types.AppServer) types.AppServer {
                return &aggregatedAppServer{
                    AppServer: latest,
                    features:  intersectComponentFeaturesApp(servers),
                }
            },
        )
    case types.DatabaseServer:
    case types.KubeServer:
    case serverResource:
    default:
        // [existing aggregation]...
    }
}
```

No changes are needed in `HeartbeatV2` itself. It continues to call `GetResource` and sends whatever `AppServerV3` it's
given. Auth’s inventory layer persists those `AppServerV3` records and makes them visible through the presence/inventory
APIs that Proxy and `tctl` already use.

#### Auth and Proxy

Auth participates in the bulk of the Resource Constraints implementation, as it must parse and enforce
`ResourceAccessID`s in Access Requests and certificates. Unlike App Service, Auth does not heartbeat via presence; it
provides `UpsertAuthServer` as the heartbeat announcer. Extending Auth's `ServerSpecV2` to add a
`ComponentFeatures` field will allow Proxy and other consumers to read Auth's feature set via existing APIs:

```go
heartbeat, err := srv.NewHeartbeat(srv.HeartbeatConfig{
    Mode:      srv.HeartbeatModeAuth,
    Context:   process.GracefulExitContext(),
    Component: teleport.ComponentAuth,
    Announcer: authServer,
    GetServerInfo: func() (types.Resource, error) {
        srv := types.ServerV2{
            Kind:    types.KindAuthServer,
            Version: types.V2,
            Metadata: types.Metadata{
                Namespace: apidefaults.Namespace,
                Name:      connector.HostUUID(),
            },
            Spec: types.ServerSpecV2{
                Addr:     authAddr,
                Hostname: process.Config.Hostname,
                Version:  teleport.Version,
				ComponentFeatures: &presence.ComponentFeatures{
                    Features: []presence.ComponentFeatureID{
						presence.COMPONENT_FEATURE_ID_RESOURCE_CONSTRAINTS_V1,
                    },
                },
            },
        }
		// [...]
        return &srv, nil
    },
	// [...]
})
```

When serving Web APIs such as `ClusterUnifiedResourcesGet` (used by the Web UI to list resources as `UnifiedResource`
records), Proxy:

1. Uses its Auth `accessPoint` to `ListAuthServers()` and `ListProxies()`, computing the intersection of all Auth and
   Proxy servers' `ComponentFeatures`, then
2. Intersects that with each `AppServerV3` presence record backing a given AWS Console app, then
3. Sets a flag (e.g., `SupportsResourceConstraints`) from that intersection on the relevant `UnifiedResource` record.

Web UI can then check `SupportsResourceConstraints` on each `UnifiedResource`, instead of working directly with
feature IDs and/or relying on `kind == app && subKind == awsConsole`.

> [!NOTE]
> This RFD is concerned with avoiding incorrect assumptions about Auth and agent capabilities in mixed-version clusters.
> It does not attempt to solve potential version skew between Proxy and Web UI themselves; that continues to rely on
> the usual API compatibility guarantees. Adding some `GetProxyServerFeatures` endpoint that returns a
> `ComponentFeatures` payload for the current Proxy instance would also involve moving some or all of the intersection
> logic into the Web UI, which has its own trade-offs with regard to complexity.

## Compatibility

Backwards compatibility is straightforward. Services that do not yet publish a features payload are treated as
supporting no features. Older readers that encounter an unknown enum value simply ignore it, so intersections naturally
degrade to the set of features both sides understand.

Forward compatibility follows the same pattern. New enum values can be appended without affecting older readers and
intersections remain safe. If we ever need non-Boolean data or a different shape, we can introduce a new field within
`ComponentFeatures` (e.g., `FeatureDetails`).

### Feature lifecycle & deprecation

Since features are identified by stable enum values, they should be treated as effectively permanent once introduced.
If a feature becomes obsolete, it can be marked as deprecated in the enum documentation, but its ID must not be reused
or removed, and advertisements of the feature should continue.

## Caveats and guidance

**No dynamic flags:** Do not use this mechanism to advertise runtime settings or mutable state. A service’s advertised
feature set must be stable for the lifetime of the process (or at least between heartbeats without mid-cycle toggling).

**Not a config/health channel:** Do not encode configuration values, environment health, or per-tenant state as
"features". If richer or non-Boolean data is ever needed for coordination, we should introduce a separate, purpose-built
payload or evolve `ComponentFeatures` with a new field that does not change per-request.

**Agentless resources require explicit handling:** The advertising model assumes a serving agent that heartbeats its own
capability. An agentless resource has nothing to advertise, so before adding `ComponentFeatures` to a new kind, check
whether it can reach presence agentless and add that derivation in `GetEffectiveServerFeatures`. Do not derive from type
for agent-served resources, that discards the agent's advertisement and would assume support an older agent does not have.
See [Agentless resources](#agentless-resources).

**Keep the field server-managed:** Only a serving agent's heartbeat should set `ComponentFeatures`, the same way `status`
and `revision` are not client-set. Client writes must nil it so a client can't claim support a resource doesn't have.
