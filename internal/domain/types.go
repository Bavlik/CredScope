// Package domain contains the stable, serialization-safe vocabulary shared by
// adapters, analyzers, and reporters. Secret material is deliberately absent.
package domain

import "time"

const (
	SchemaVersion = "2.0.0"
	ScoringPolicy = "v2"
)

type Classification string

const (
	ClassificationSecret                 Classification = "secret"
	ClassificationCredential             Classification = "credential"
	ClassificationCredentialIdentifier   Classification = "credential_identifier"
	ClassificationSensitiveConfiguration Classification = "sensitive_configuration"
	ClassificationPublicConfiguration    Classification = "public_configuration"
	ClassificationOperationalSetting     Classification = "operational_setting"
	ClassificationUnknown                Classification = "unknown"
)

type Profile string

const (
	ProfileAuto       Profile = "auto"
	ProfileLocal      Profile = "local"
	ProfileCI         Profile = "ci"
	ProfileStaging    Profile = "staging"
	ProfileProduction Profile = "production"
)

type ProfileSelection struct {
	Requested   Profile  `json:"requested"`
	Selected    Profile  `json:"selected"`
	Source      string   `json:"source"`
	Reason      string   `json:"reason"`
	Assumptions []string `json:"assumptions"`
}

type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceHigh      Confidence = "high"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceLow       Confidence = "low"
	ConfidenceUnknown   Confidence = "unknown"
)

type Severity string

const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

// Location is always repository-relative when it originates from analyzed
// content. Line and Column are one-based; zero means unavailable.
type Location struct {
	Path   string `json:"path" yaml:"path"`
	Line   int    `json:"line,omitempty" yaml:"line,omitempty"`
	Column int    `json:"column,omitempty" yaml:"column,omitempty"`
}

type Evidence struct {
	RuleID      string     `json:"rule_id"`
	Type        string     `json:"type,omitempty"`
	Description string     `json:"description"`
	Location    Location   `json:"location"`
	Field       string     `json:"field,omitempty"`
	Source      string     `json:"source,omitempty"`
	Confidence  Confidence `json:"confidence"`
}

// CredentialIdentity is safe to serialize. Fingerprint is an irreversible,
// domain-separated SHA-256 identifier; Label is a reference name, never a value.
type CredentialIdentity struct {
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Type        string `json:"type,omitempty"`
}

// Finding is the scanner-neutral representation accepted by future adapters.
// There is intentionally no RawSecret, Match, or Secret field.
type Finding struct {
	ID                   string             `json:"id"`
	RuleID               string             `json:"rule_id"`
	Description          string             `json:"description"`
	Credential           CredentialIdentity `json:"credential"`
	Location             Location           `json:"location"`
	Commit               string             `json:"commit,omitempty"`
	CommitInfo           *CommitMetadata    `json:"commit_info,omitempty"`
	Tags                 []string           `json:"tags,omitempty"`
	Source               string             `json:"source"`
	TestFixtureCandidate bool               `json:"test_fixture_candidate"`
}

// CommitMetadata intentionally excludes the commit message body because it may
// contain credential material. MessageFingerprint permits stable correlation.
type CommitMetadata struct {
	Author             string `json:"author,omitempty"`
	Email              string `json:"email,omitempty"`
	Date               string `json:"date,omitempty"`
	MessageFingerprint string `json:"message_fingerprint,omitempty"`
}

type NodeType string

const (
	NodeCredential       NodeType = "credential"
	NodeFinding          NodeType = "finding"
	NodeFile             NodeType = "file"
	NodeWorkflow         NodeType = "workflow"
	NodeTrigger          NodeType = "trigger"
	NodeJob              NodeType = "job"
	NodeStep             NodeType = "step"
	NodePermission       NodeType = "permission"
	NodeEnvironment      NodeType = "environment"
	NodeComposeService   NodeType = "compose_service"
	NodePortExposure     NodeType = "port_exposure"
	NodeVolumeMount      NodeType = "volume_mount"
	NodeExternalAction   NodeType = "external_action"
	NodeReusableWorkflow NodeType = "reusable_workflow"
	NodeComposeSecret    NodeType = "compose_secret"
	NodeEnvFile          NodeType = "env_file"
	NodeRepository       NodeType = "repository"
)

type EdgeType string

const (
	EdgeConfiguredIn          EdgeType = "configured_in"
	EdgeAvailableToService    EdgeType = "available_to_service"
	EdgeAvailableToProcess    EdgeType = "available_to_process"
	EdgeReferencedByProcess   EdgeType = "referenced_by_process"
	EdgeMountedAsSecret       EdgeType = "mounted_as_secret"
	EdgeExplicitlyForwardedTo EdgeType = "explicitly_forwarded_to"
	EdgeDependsOn             EdgeType = "depends_on"
	EdgeNetworkReachable      EdgeType = "network_reachable"
	EdgeExposesPort           EdgeType = "exposes_port"
	EdgeReadsEnvFile          EdgeType = "reads_env_file"
	EdgeDetectedIn            EdgeType = "detected_in"
	EdgeBelongsTo             EdgeType = "belongs_to"
	EdgeTriggeredBy           EdgeType = "triggered_by"
	EdgeHasPermission         EdgeType = "has_permission"
	EdgeUsesEnvironment       EdgeType = "uses_environment"
	EdgeRunsAction            EdgeType = "runs_action"
	EdgeMountsVolume          EdgeType = "mounts_volume"
	EdgeCallsWorkflow         EdgeType = "calls_workflow"
)

// Backward-compatible names for embedders compiling against v0.1.0. Their
// serialized values use the corrected v2 relationship vocabulary.
const (
	EdgeReferencedBy  = EdgeConfiguredIn
	EdgeExposedTo     = EdgeAvailableToProcess
	EdgePassedTo      = EdgeExplicitlyForwardedTo
	EdgeExecutedBy    = EdgeBelongsTo
	EdgeDeploysTo     = EdgeUsesEnvironment
	EdgePublishesPort = EdgeExposesPort
	EdgeMounts        = EdgeMountsVolume
	EdgeUsesSecret    = EdgeMountedAsSecret
	EdgeLoadsEnvFile  = EdgeReadsEnvFile
	EdgeSharedWith    = EdgeNetworkReachable
	EdgePropagatesTo  = EdgeExplicitlyForwardedTo
)

type EvidenceKind string

const (
	EvidenceConfirmedDataFlow EvidenceKind = "confirmed_static_data_flow"
	EvidenceExposureContext   EvidenceKind = "inferred_exposure_context"
	EvidenceNetworkTopology   EvidenceKind = "network_topology_only"
	EvidenceUnknownRuntime    EvidenceKind = "unknown_runtime_behavior"
)

type Node struct {
	ID         string            `json:"id"`
	Type       NodeType          `json:"type"`
	Label      string            `json:"label"`
	Location   *Location         `json:"location,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Evidence   []Evidence        `json:"evidence,omitempty"`
	Confidence Confidence        `json:"confidence"`
}

type Edge struct {
	ID           string       `json:"id"`
	From         string       `json:"from"`
	To           string       `json:"to"`
	Type         EdgeType     `json:"type"`
	EvidenceKind EvidenceKind `json:"evidence_kind"`
	Evidence     []Evidence   `json:"evidence,omitempty"`
	Confidence   Confidence   `json:"confidence"`
}

type ScoreFactor struct {
	RuleID       string     `json:"rule_id"`
	Description  string     `json:"description"`
	Weight       int        `json:"weight"`
	Contribution int        `json:"contribution"`
	Evidence     []Evidence `json:"evidence"`
	Remediation  string     `json:"remediation"`
	Confidence   Confidence `json:"confidence"`
}

type IgnoredItem struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type Recommendation struct {
	RuleID      string     `json:"rule_id"`
	Title       string     `json:"title"`
	Why         string     `json:"why"`
	Remediation string     `json:"remediation"`
	Evidence    []Evidence `json:"evidence"`
}

type CredentialAssessment struct {
	Credential      CredentialIdentity `json:"credential"`
	Score           int                `json:"score"`
	Severity        Severity           `json:"severity"`
	Confidence      Confidence         `json:"confidence"`
	Factors         []ScoreFactor      `json:"factors"`
	Recommendations []Recommendation   `json:"recommendations"`
}

type ScanMetadata struct {
	RepositoryRoot string    `json:"repository_root"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	SchemaVersion  string    `json:"schema_version"`
	ScoringPolicy  string    `json:"scoring_policy"`
}

type Report struct {
	Metadata    ScanMetadata           `json:"metadata"`
	Findings    []Finding              `json:"findings"`
	Nodes       []Node                 `json:"graph_nodes"`
	Edges       []Edge                 `json:"graph_edges"`
	Credentials []CredentialAssessment `json:"credentials"`
	Warnings    []string               `json:"warnings"`
	Errors      []string               `json:"errors"`
}
