// Package internal — Hover typed IaC gRPC server.
//
// hoverIaCServer wraps *HoverProvider and satisfies the pb.IaCProvider*Server
// interface set required by sdk.ServeIaCPlugin. The shape mirrors
// workflow-plugin-digitalocean/internal/iacserver.go; only the provider-
// specific dial surface differs.
//
// Hard invariants:
//   - NO structpb.Struct on the wire; config / outputs cross as JSON bytes.
//   - ComputePlanVersion "v2" (Apply is removed; FinalizeApply returns empty
//     since Hover has no deferred operations).
//   - sdk.ServeIaCPlugin auto-registers every typed pb.IaCProvider*Server
//     interface this struct satisfies (see internal/serve.go). hoverIaCServer
//     embeds pb.Unimplemented*Server for the full surface
//     (Required + Finalizer + DriftDetector + Enumerator + Validator +
//     DriftConfigDetector + CredentialRevoker + MigrationRepairer +
//     ResourceDriver + PluginService), so every service registers — but
//     Hover only implements method bodies for Required + Finalizer +
//     DriftDetector. The unimplemented services respond with a typed
//     "Unimplemented" gRPC status rather than "service not registered",
//     which is the right shape for cross-plugin uniformity but means
//     clients must check capabilities before invoking optional methods.
package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/GoCodeAlone/workflow/interfaces"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// hoverIaCServer wraps *HoverProvider and exposes the typed pb.IaCProvider*Server
// surface required by sdk.ServeIaCPlugin.
type hoverIaCServer struct {
	pb.UnimplementedIaCProviderRequiredServer
	pb.UnimplementedIaCProviderDriftDetectorServer
	pb.UnimplementedIaCProviderEnumeratorServer
	pb.UnimplementedIaCProviderCredentialRevokerServer
	pb.UnimplementedIaCProviderMigrationRepairerServer
	pb.UnimplementedIaCProviderValidatorServer
	pb.UnimplementedIaCProviderDriftConfigDetectorServer
	pb.UnimplementedIaCProviderFinalizerServer
	pb.UnimplementedResourceDriverServer
	pb.UnimplementedPluginServiceServer
	pb.UnimplementedIaCStateBackendServer

	provider *HoverProvider
}

// Compile-time interface assertions.
var (
	_ pb.IaCProviderRequiredServer      = (*hoverIaCServer)(nil)
	_ pb.IaCProviderDriftDetectorServer = (*hoverIaCServer)(nil)
	_ pb.IaCProviderFinalizerServer     = (*hoverIaCServer)(nil)
)

// NewIaCServer is the package entrypoint for cmd/main.go.
func NewIaCServer() *hoverIaCServer {
	return &hoverIaCServer{provider: NewHoverProvider()}
}

// ── Required service ──────────────────────────────────────────────────────────

func (s *hoverIaCServer) Initialize(ctx context.Context, req *pb.InitializeRequest) (*pb.InitializeResponse, error) {
	cfg, err := unmarshalJSONMap(req.GetConfigJson())
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: parse Initialize config_json: %w", err)
	}
	if err := s.provider.Initialize(ctx, cfg); err != nil {
		return nil, err
	}
	return &pb.InitializeResponse{}, nil
}

func (s *hoverIaCServer) Name(_ context.Context, _ *pb.NameRequest) (*pb.NameResponse, error) {
	return &pb.NameResponse{Name: s.provider.Name()}, nil
}

func (s *hoverIaCServer) Version(_ context.Context, _ *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{Version: s.provider.Version()}, nil
}

func (s *hoverIaCServer) Capabilities(_ context.Context, _ *pb.CapabilitiesRequest) (*pb.CapabilitiesResponse, error) {
	caps := s.provider.Capabilities()
	out := make([]*pb.IaCCapabilityDeclaration, 0, len(caps))
	for _, c := range caps {
		tier := c.Tier
		if tier < math.MinInt32 {
			tier = math.MinInt32
		} else if tier > math.MaxInt32 {
			tier = math.MaxInt32
		}
		out = append(out, &pb.IaCCapabilityDeclaration{
			ResourceType: c.ResourceType,
			Tier:         int32(tier), //nolint:gosec // G115: clamped above
			Operations:   append([]string(nil), c.Operations...),
		})
	}
	return &pb.CapabilitiesResponse{
		Capabilities:       out,
		ComputePlanVersion: "v2",
	}, nil
}

func (s *hoverIaCServer) Plan(ctx context.Context, req *pb.PlanRequest) (*pb.PlanResponse, error) {
	desired, err := specsFromPB(req.GetDesired())
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: decode Plan desired: %w", err)
	}
	current, err := statesFromPB(req.GetCurrent())
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: decode Plan current: %w", err)
	}
	plan, err := s.provider.Plan(ctx, desired, current)
	if err != nil {
		return nil, err
	}
	pbPlan, err := planToPB(plan)
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: encode Plan response: %w", err)
	}
	return &pb.PlanResponse{Plan: pbPlan}, nil
}

func (s *hoverIaCServer) Destroy(ctx context.Context, req *pb.DestroyRequest) (*pb.DestroyResponse, error) {
	refs := refsFromPB(req.GetRefs())
	result, err := s.provider.Destroy(ctx, refs)
	if err != nil {
		return nil, err
	}
	return &pb.DestroyResponse{Result: destroyResultToPB(result)}, nil
}

func (s *hoverIaCServer) Status(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	refs := refsFromPB(req.GetRefs())
	statuses, err := s.provider.Status(ctx, refs)
	if err != nil {
		return nil, err
	}
	pbStatuses, err := statusesToPB(statuses)
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: encode Status response: %w", err)
	}
	return &pb.StatusResponse{Statuses: pbStatuses}, nil
}

func (s *hoverIaCServer) Import(ctx context.Context, req *pb.ImportRequest) (*pb.ImportResponse, error) {
	_, err := s.provider.Import(ctx, req.GetProviderId(), req.GetResourceType())
	if err != nil {
		return nil, err
	}
	return &pb.ImportResponse{}, nil
}

func (s *hoverIaCServer) ResolveSizing(_ context.Context, _ *pb.ResolveSizingRequest) (*pb.ResolveSizingResponse, error) {
	return nil, fmt.Errorf("hover: ResolveSizing is not supported")
}

func (s *hoverIaCServer) BootstrapStateBackend(_ context.Context, _ *pb.BootstrapStateBackendRequest) (*pb.BootstrapStateBackendResponse, error) {
	return &pb.BootstrapStateBackendResponse{}, nil
}

// FinalizeApply satisfies pb.IaCProviderFinalizerServer. Hover has no
// deferred operations so this is always a no-op empty success.
func (s *hoverIaCServer) FinalizeApply(_ context.Context, _ *pb.FinalizeApplyRequest) (*pb.FinalizeApplyResponse, error) {
	return &pb.FinalizeApplyResponse{}, nil
}

// ── Drift detection ───────────────────────────────────────────────────────────

func (s *hoverIaCServer) DetectDrift(ctx context.Context, req *pb.DetectDriftRequest) (*pb.DetectDriftResponse, error) {
	refs := refsFromPB(req.GetRefs())
	drifts, err := s.provider.DetectDrift(ctx, refs)
	if err != nil {
		return nil, err
	}
	pbDrifts, err := driftsToPB(drifts)
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: encode DetectDrift response: %w", err)
	}
	return &pb.DetectDriftResponse{Drifts: pbDrifts}, nil
}

// ── ResourceDriver service ───────────────────────────────────────────────────

func (s *hoverIaCServer) Create(ctx context.Context, req *pb.ResourceCreateRequest) (*pb.ResourceCreateResponse, error) {
	driver, err := s.provider.ResourceDriver(req.GetResourceType())
	if err != nil {
		return nil, err
	}
	spec, err := specFromPB(req.GetSpec())
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: decode Create spec: %w", err)
	}
	out, err := driver.Create(ctx, spec)
	if err != nil {
		return nil, err
	}
	pbOut, err := outputToPB(out)
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: encode Create output: %w", err)
	}
	return &pb.ResourceCreateResponse{Output: pbOut}, nil
}

func (s *hoverIaCServer) Read(ctx context.Context, req *pb.ResourceReadRequest) (*pb.ResourceReadResponse, error) {
	driver, err := s.provider.ResourceDriver(req.GetResourceType())
	if err != nil {
		return nil, err
	}
	out, err := driver.Read(ctx, refFromPB(req.GetRef()))
	if err != nil {
		return nil, err
	}
	pbOut, err := outputToPB(out)
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: encode Read output: %w", err)
	}
	return &pb.ResourceReadResponse{Output: pbOut}, nil
}

func (s *hoverIaCServer) Update(ctx context.Context, req *pb.ResourceUpdateRequest) (*pb.ResourceUpdateResponse, error) {
	driver, err := s.provider.ResourceDriver(req.GetResourceType())
	if err != nil {
		return nil, err
	}
	spec, err := specFromPB(req.GetSpec())
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: decode Update spec: %w", err)
	}
	out, err := driver.Update(ctx, refFromPB(req.GetRef()), spec)
	if err != nil {
		return nil, err
	}
	pbOut, err := outputToPB(out)
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: encode Update output: %w", err)
	}
	return &pb.ResourceUpdateResponse{Output: pbOut}, nil
}

func (s *hoverIaCServer) Delete(ctx context.Context, req *pb.ResourceDeleteRequest) (*pb.ResourceDeleteResponse, error) {
	driver, err := s.provider.ResourceDriver(req.GetResourceType())
	if err != nil {
		return nil, err
	}
	if err := driver.Delete(ctx, refFromPB(req.GetRef())); err != nil {
		return nil, err
	}
	return &pb.ResourceDeleteResponse{}, nil
}

func (s *hoverIaCServer) Diff(ctx context.Context, req *pb.ResourceDiffRequest) (*pb.ResourceDiffResponse, error) {
	driver, err := s.provider.ResourceDriver(req.GetResourceType())
	if err != nil {
		return nil, err
	}
	spec, err := specFromPB(req.GetDesired())
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: decode Diff desired: %w", err)
	}
	current, err := outputFromPB(req.GetCurrent())
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: decode Diff current: %w", err)
	}
	diff, err := driver.Diff(ctx, spec, current)
	if err != nil {
		return nil, err
	}
	pbDiff, err := diffResultToPB(diff)
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: encode Diff result: %w", err)
	}
	return &pb.ResourceDiffResponse{Result: pbDiff}, nil
}

func (s *hoverIaCServer) Scale(ctx context.Context, req *pb.ResourceScaleRequest) (*pb.ResourceScaleResponse, error) {
	driver, err := s.provider.ResourceDriver(req.GetResourceType())
	if err != nil {
		return nil, err
	}
	out, err := driver.Scale(ctx, refFromPB(req.GetRef()), int(req.GetReplicas()))
	if err != nil {
		return nil, err
	}
	pbOut, err := outputToPB(out)
	if err != nil {
		return nil, fmt.Errorf("hover iacserver: encode Scale output: %w", err)
	}
	return &pb.ResourceScaleResponse{Output: pbOut}, nil
}

func (s *hoverIaCServer) HealthCheck(ctx context.Context, req *pb.ResourceHealthCheckRequest) (*pb.ResourceHealthCheckResponse, error) {
	driver, err := s.provider.ResourceDriver(req.GetResourceType())
	if err != nil {
		return nil, err
	}
	result, err := driver.HealthCheck(ctx, refFromPB(req.GetRef()))
	if err != nil {
		return nil, err
	}
	if result == nil {
		return &pb.ResourceHealthCheckResponse{}, nil
	}
	return &pb.ResourceHealthCheckResponse{Result: &pb.HealthResult{Healthy: result.Healthy, Message: result.Message}}, nil
}

func (s *hoverIaCServer) SensitiveKeys(_ context.Context, req *pb.SensitiveKeysRequest) (*pb.SensitiveKeysResponse, error) {
	driver, err := s.provider.ResourceDriver(req.GetResourceType())
	if err != nil {
		return nil, err
	}
	return &pb.SensitiveKeysResponse{Keys: append([]string(nil), driver.SensitiveKeys()...)}, nil
}

// ── Marshalling helpers ───────────────────────────────────────────────────────

func unmarshalJSONMap(b []byte) (map[string]any, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func marshalJSONMap(m map[string]any) ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

func marshalJSONAny(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

func unmarshalJSONAny(b []byte) (any, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func refFromPB(r *pb.ResourceRef) interfaces.ResourceRef {
	if r == nil {
		return interfaces.ResourceRef{}
	}
	return interfaces.ResourceRef{Name: r.GetName(), Type: r.GetType(), ProviderID: r.GetProviderId()}
}

func refsFromPB(refs []*pb.ResourceRef) []interfaces.ResourceRef {
	out := make([]interfaces.ResourceRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, refFromPB(r))
	}
	return out
}

func hintsFromPB(h *pb.ResourceHints) *interfaces.ResourceHints {
	if h == nil {
		return nil
	}
	return &interfaces.ResourceHints{CPU: h.GetCpu(), Memory: h.GetMemory(), Storage: h.GetStorage()}
}

func specFromPB(s *pb.ResourceSpec) (interfaces.ResourceSpec, error) {
	if s == nil {
		return interfaces.ResourceSpec{}, nil
	}
	cfg, err := unmarshalJSONMap(s.GetConfigJson())
	if err != nil {
		return interfaces.ResourceSpec{}, err
	}
	return interfaces.ResourceSpec{
		Name:      s.GetName(),
		Type:      s.GetType(),
		Config:    cfg,
		Size:      interfaces.Size(s.GetSize()),
		Hints:     hintsFromPB(s.GetHints()),
		DependsOn: append([]string(nil), s.GetDependsOn()...),
	}, nil
}

func specsFromPB(specs []*pb.ResourceSpec) ([]interfaces.ResourceSpec, error) {
	out := make([]interfaces.ResourceSpec, 0, len(specs))
	for _, s := range specs {
		gs, err := specFromPB(s)
		if err != nil {
			return nil, err
		}
		out = append(out, gs)
	}
	return out, nil
}

func stateFromPB(s *pb.ResourceState) (*interfaces.ResourceState, error) {
	if s == nil {
		return nil, nil
	}
	applied, err := unmarshalJSONMap(s.GetAppliedConfigJson())
	if err != nil {
		return nil, err
	}
	outputs, err := unmarshalJSONMap(s.GetOutputsJson())
	if err != nil {
		return nil, err
	}
	return &interfaces.ResourceState{
		ID:                  s.GetId(),
		Name:                s.GetName(),
		Type:                s.GetType(),
		Provider:            s.GetProvider(),
		ProviderRef:         s.GetProviderRef(),
		ProviderID:          s.GetProviderId(),
		ConfigHash:          s.GetConfigHash(),
		AppliedConfig:       applied,
		AppliedConfigSource: s.GetAppliedConfigSource(),
		Outputs:             outputs,
		Dependencies:        append([]string(nil), s.GetDependencies()...),
		CreatedAt:           timeFromPB(s.GetCreatedAt()),
		UpdatedAt:           timeFromPB(s.GetUpdatedAt()),
		LastDriftCheck:      timeFromPB(s.GetLastDriftCheck()),
	}, nil
}

func statesFromPB(states []*pb.ResourceState) ([]interfaces.ResourceState, error) {
	out := make([]interfaces.ResourceState, 0, len(states))
	for _, s := range states {
		gs, err := stateFromPB(s)
		if err != nil {
			return nil, err
		}
		if gs != nil {
			out = append(out, *gs)
		}
	}
	return out, nil
}

func stateToPB(st *interfaces.ResourceState) (*pb.ResourceState, error) {
	if st == nil {
		return nil, nil
	}
	appliedJSON, err := marshalJSONMap(st.AppliedConfig)
	if err != nil {
		return nil, err
	}
	outputsJSON, err := marshalJSONMap(st.Outputs)
	if err != nil {
		return nil, err
	}
	return &pb.ResourceState{
		Id:                  st.ID,
		Name:                st.Name,
		Type:                st.Type,
		Provider:            st.Provider,
		ProviderRef:         st.ProviderRef,
		ProviderId:          st.ProviderID,
		ConfigHash:          st.ConfigHash,
		AppliedConfigJson:   appliedJSON,
		AppliedConfigSource: st.AppliedConfigSource,
		OutputsJson:         outputsJSON,
		Dependencies:        append([]string(nil), st.Dependencies...),
		CreatedAt:           timeToPB(st.CreatedAt),
		UpdatedAt:           timeToPB(st.UpdatedAt),
		LastDriftCheck:      timeToPB(st.LastDriftCheck),
	}, nil
}

func specToPB(s interfaces.ResourceSpec) (*pb.ResourceSpec, error) {
	cfgJSON, err := marshalJSONMap(s.Config)
	if err != nil {
		return nil, err
	}
	var hintsPB *pb.ResourceHints
	if s.Hints != nil {
		hintsPB = &pb.ResourceHints{Cpu: s.Hints.CPU, Memory: s.Hints.Memory, Storage: s.Hints.Storage}
	}
	return &pb.ResourceSpec{
		Name:       s.Name,
		Type:       s.Type,
		ConfigJson: cfgJSON,
		Size:       string(s.Size),
		Hints:      hintsPB,
		DependsOn:  append([]string(nil), s.DependsOn...),
	}, nil
}

func changesToPB(changes []interfaces.FieldChange) ([]*pb.FieldChange, error) {
	out := make([]*pb.FieldChange, 0, len(changes))
	for _, c := range changes {
		oldJSON, err := marshalJSONAny(c.Old)
		if err != nil {
			return nil, err
		}
		newJSON, err := marshalJSONAny(c.New)
		if err != nil {
			return nil, err
		}
		out = append(out, &pb.FieldChange{
			Path:     c.Path,
			OldJson:  oldJSON,
			NewJson:  newJSON,
			ForceNew: c.ForceNew,
		})
	}
	return out, nil
}

func planActionToPB(a interfaces.PlanAction) (*pb.PlanAction, error) {
	pbSpec, err := specToPB(a.Resource)
	if err != nil {
		return nil, err
	}
	var pbCurrent *pb.ResourceState
	if a.Current != nil {
		pbCurrent, err = stateToPB(a.Current)
		if err != nil {
			return nil, err
		}
	}
	pbChanges, err := changesToPB(a.Changes)
	if err != nil {
		return nil, err
	}
	return &pb.PlanAction{
		Action:             a.Action,
		Resource:           pbSpec,
		Current:            pbCurrent,
		Changes:            pbChanges,
		ResolvedConfigHash: a.ResolvedConfigHash,
	}, nil
}

func planToPB(p *interfaces.IaCPlan) (*pb.IaCPlan, error) {
	if p == nil {
		return nil, nil
	}
	pbActions := make([]*pb.PlanAction, 0, len(p.Actions))
	for i := range p.Actions {
		pa, err := planActionToPB(p.Actions[i])
		if err != nil {
			return nil, err
		}
		pbActions = append(pbActions, pa)
	}
	if p.SchemaVersion < math.MinInt32 || p.SchemaVersion > math.MaxInt32 {
		return nil, fmt.Errorf("hover iacserver: plan SchemaVersion %d out of int32 range", p.SchemaVersion)
	}
	return &pb.IaCPlan{
		Id:            p.ID,
		Actions:       pbActions,
		CreatedAt:     timeToPB(p.CreatedAt),
		DesiredHash:   p.DesiredHash,
		SchemaVersion: int32(p.SchemaVersion), //nolint:gosec // G115: range-checked above
		InputSnapshot: copyStringMap(p.InputSnapshot),
	}, nil
}

func destroyResultToPB(r *interfaces.DestroyResult) *pb.DestroyResult {
	if r == nil {
		return nil
	}
	errs := make([]*pb.ActionError, 0, len(r.Errors))
	for _, e := range r.Errors {
		errs = append(errs, &pb.ActionError{Resource: e.Resource, Action: e.Action, Error: e.Error})
	}
	return &pb.DestroyResult{Destroyed: append([]string(nil), r.Destroyed...), Errors: errs}
}

func statusesToPB(ss []interfaces.ResourceStatus) ([]*pb.ResourceStatus, error) {
	out := make([]*pb.ResourceStatus, 0, len(ss))
	for i := range ss {
		o, err := marshalJSONMap(ss[i].Outputs)
		if err != nil {
			return nil, err
		}
		out = append(out, &pb.ResourceStatus{
			Name:        ss[i].Name,
			Type:        ss[i].Type,
			ProviderId:  ss[i].ProviderID,
			Status:      ss[i].Status,
			OutputsJson: o,
		})
	}
	return out, nil
}

func outputToPB(o *interfaces.ResourceOutput) (*pb.ResourceOutput, error) {
	if o == nil {
		return nil, nil
	}
	outputsJSON, err := marshalJSONMap(o.Outputs)
	if err != nil {
		return nil, err
	}
	return &pb.ResourceOutput{
		Name:        o.Name,
		Type:        o.Type,
		ProviderId:  o.ProviderID,
		OutputsJson: outputsJSON,
		Sensitive:   copyBoolMap(o.Sensitive),
		Status:      o.Status,
	}, nil
}

func outputFromPB(o *pb.ResourceOutput) (*interfaces.ResourceOutput, error) {
	if o == nil {
		return nil, nil
	}
	outputs, err := unmarshalJSONMap(o.GetOutputsJson())
	if err != nil {
		return nil, err
	}
	return &interfaces.ResourceOutput{
		Name:       o.GetName(),
		Type:       o.GetType(),
		ProviderID: o.GetProviderId(),
		Outputs:    outputs,
		Sensitive:  copyBoolMap(o.GetSensitive()),
		Status:     o.GetStatus(),
	}, nil
}

func diffResultToPB(d *interfaces.DiffResult) (*pb.DiffResult, error) {
	if d == nil {
		return nil, nil
	}
	changes, err := changesToPB(d.Changes)
	if err != nil {
		return nil, err
	}
	return &pb.DiffResult{
		NeedsUpdate:  d.NeedsUpdate,
		NeedsReplace: d.NeedsReplace,
		Changes:      changes,
	}, nil
}

func copyBoolMap(in map[string]bool) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func driftClassToPB(c interfaces.DriftClass) pb.DriftClass {
	switch c {
	case interfaces.DriftClassInSync:
		return pb.DriftClass_DRIFT_CLASS_IN_SYNC
	case interfaces.DriftClassGhost:
		return pb.DriftClass_DRIFT_CLASS_GHOST
	case interfaces.DriftClassConfig:
		return pb.DriftClass_DRIFT_CLASS_CONFIG
	default:
		return pb.DriftClass_DRIFT_CLASS_UNKNOWN
	}
}

func driftsToPB(drifts []interfaces.DriftResult) ([]*pb.DriftResult, error) {
	out := make([]*pb.DriftResult, 0, len(drifts))
	for _, d := range drifts {
		expectedJSON, err := marshalJSONMap(d.Expected)
		if err != nil {
			return nil, err
		}
		actualJSON, err := marshalJSONMap(d.Actual)
		if err != nil {
			return nil, err
		}
		out = append(out, &pb.DriftResult{
			Name:         d.Name,
			Type:         d.Type,
			Drifted:      d.Drifted,
			Class:        driftClassToPB(d.Class),
			ExpectedJson: expectedJSON,
			ActualJson:   actualJSON,
			Fields:       append([]string(nil), d.Fields...),
		})
	}
	return out, nil
}

func timeToPB(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func timeFromPB(t *timestamppb.Timestamp) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.AsTime()
}

func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
