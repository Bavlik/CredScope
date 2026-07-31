package domain

// ReferenceKind identifies a safe expression reference, never its resolved value.
type ReferenceKind string

const (
	ReferenceSecret          ReferenceKind = "secret"
	ReferenceEnvironment     ReferenceKind = "environment"
	ReferenceGitHubContext   ReferenceKind = "github_context"
	ReferenceComposeVariable ReferenceKind = "compose_variable"
	ReferenceComposeSecret   ReferenceKind = "compose_secret"
	// ReferenceActionInput identifies ${{ inputs.<name> }} usage inside a
	// composite action's own metadata. It is deliberately distinct from
	// ReferenceGitHubContext's existing "inputs.*" dangerous-context
	// handling, which models a workflow's own workflow_dispatch/
	// workflow_call caller-supplied inputs — a different, unrelated scope.
	ReferenceActionInput ReferenceKind = "action_input"
)

type Reference struct {
	Kind       ReferenceKind `json:"kind"`
	Name       string        `json:"name"`
	Expression string        `json:"expression,omitempty"`
	Evidence   Evidence      `json:"evidence"`
}

type StructuralSignal struct {
	Kind        string     `json:"kind"`
	Description string     `json:"description"`
	Confidence  Confidence `json:"confidence"`
	Evidence    Evidence   `json:"evidence"`
}

type ParseWarning struct {
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Location Location `json:"location"`
	Source   string   `json:"source"`
}

type Permission struct {
	Scope    string   `json:"scope"`
	Level    string   `json:"level"`
	Evidence Evidence `json:"evidence"`
}

type EnvironmentBinding struct {
	Name               string      `json:"name"`
	Scope              string      `json:"scope"`
	References         []Reference `json:"references"`
	HasLiteral         bool        `json:"has_literal"`
	LiteralFingerprint string      `json:"literal_fingerprint,omitempty"`
	Evidence           Evidence    `json:"evidence"`
}

type WorkflowTrigger struct {
	Name     string   `json:"name"`
	Evidence Evidence `json:"evidence"`
}

type ActionReference struct {
	Reference    string   `json:"reference"`
	Owner        string   `json:"owner,omitempty"`
	Repository   string   `json:"repository,omitempty"`
	Revision     string   `json:"revision,omitempty"`
	Local        bool     `json:"local"`
	Docker       bool     `json:"docker"`
	ThirdParty   bool     `json:"third_party"`
	PinnedSHA    bool     `json:"pinned_sha"`
	Mutable      bool     `json:"mutable"`
	ArtifactKind string   `json:"artifact_kind,omitempty"`
	Evidence     Evidence `json:"evidence"`
}

type ShellCommand struct {
	RedactedText string      `json:"redacted_text"`
	Fingerprint  string      `json:"fingerprint"`
	LineCount    int         `json:"line_count"`
	References   []Reference `json:"references"`
	Evidence     Evidence    `json:"evidence"`
}

type WorkflowOutput struct {
	Name       string      `json:"name"`
	References []Reference `json:"references"`
	Evidence   Evidence    `json:"evidence"`
}

type WorkflowStep struct {
	ID          string               `json:"id,omitempty"`
	Name        string               `json:"name,omitempty"`
	Action      *ActionReference     `json:"action,omitempty"`
	Run         *ShellCommand        `json:"run,omitempty"`
	Environment []EnvironmentBinding `json:"environment"`
	References  []Reference          `json:"references"`
	Evidence    Evidence             `json:"evidence"`
}

// ReusableWorkflowInput is a single job-level `with:` entry on a reusable
// workflow call. References capture expressions found in the caller-side value.
type ReusableWorkflowInput struct {
	Name       string      `json:"name"`
	References []Reference `json:"references"`
	Evidence   Evidence    `json:"evidence"`
}

// ReusableWorkflowSecret is a single job-level `secrets:` entry on a reusable
// workflow call. Name is the callee-side secret alias; References capture
// expressions found in the caller-side value (e.g. secrets.PROD_TOKEN).
type ReusableWorkflowSecret struct {
	Name       string      `json:"name"`
	References []Reference `json:"references"`
	Evidence   Evidence    `json:"evidence"`
}

type WorkflowJob struct {
	ID                             string                   `json:"id"`
	Name                           string                   `json:"name,omitempty"`
	Needs                          []string                 `json:"needs"`
	Permissions                    []Permission             `json:"permissions"`
	Environment                    []EnvironmentBinding     `json:"environment"`
	EnvironmentName                string                   `json:"environment_name,omitempty"`
	EnvironmentEvidence            *Evidence                `json:"environment_evidence,omitempty"`
	ReusableWorkflow               *ActionReference         `json:"reusable_workflow,omitempty"`
	ReusableResolved               bool                     `json:"reusable_resolved"`
	ReusableWorkflowInputs         []ReusableWorkflowInput  `json:"reusable_workflow_inputs,omitempty"`
	ReusableWorkflowSecrets        []ReusableWorkflowSecret `json:"reusable_workflow_secrets,omitempty"`
	ReusableSecretsInherit         bool                     `json:"reusable_secrets_inherit,omitempty"`
	ReusableSecretsInheritEvidence *Evidence                `json:"reusable_secrets_inherit_evidence,omitempty"`
	Steps                          []WorkflowStep           `json:"steps"`
	Outputs                        []WorkflowOutput         `json:"outputs"`
	References                     []Reference              `json:"references"`
	Signals                        []StructuralSignal       `json:"signals"`
	Evidence                       Evidence                 `json:"evidence"`
}

// ReusableWorkflowInputDefault preserves a workflow_call input's declared
// scalar default without collapsing its type. Type is one of "string",
// "boolean", or "number"; exactly one of the pointer fields matching Type is
// non-nil. Pointers (not omitempty value fields) so that zero-valued
// defaults such as false, 0, or "" still serialize explicitly.
type ReusableWorkflowInputDefault struct {
	Type    string   `json:"type"`
	String  *string  `json:"string,omitempty"`
	Boolean *bool    `json:"boolean,omitempty"`
	Number  *float64 `json:"number,omitempty"`
}

// ReusableWorkflowInputDefinition is one declared `on.workflow_call.inputs`
// entry on the callee side of a reusable workflow contract.
type ReusableWorkflowInputDefinition struct {
	Name        string                        `json:"name"`
	Description string                        `json:"description,omitempty"`
	Required    bool                          `json:"required"`
	Type        string                        `json:"type"`
	Default     *ReusableWorkflowInputDefault `json:"default,omitempty"`
	Evidence    Evidence                      `json:"evidence"`
}

// ReusableWorkflowSecretDefinition is one declared `on.workflow_call.secrets`
// entry on the callee side of a reusable workflow contract.
type ReusableWorkflowSecretDefinition struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required"`
	Evidence    Evidence `json:"evidence"`
}

// ReusableWorkflowContract is the callee-side declaration made by a
// `workflow_call` trigger. A non-nil, empty contract means the workflow
// declared `workflow_call` without inputs or secrets.
type ReusableWorkflowContract struct {
	Inputs   []ReusableWorkflowInputDefinition  `json:"inputs,omitempty"`
	Secrets  []ReusableWorkflowSecretDefinition `json:"secrets,omitempty"`
	Evidence Evidence                           `json:"evidence"`
}

type Workflow struct {
	Name                       string                    `json:"name"`
	File                       string                    `json:"file"`
	Triggers                   []WorkflowTrigger         `json:"triggers"`
	Permissions                []Permission              `json:"permissions"`
	MissingExplicitPermissions bool                      `json:"missing_explicit_permissions"`
	Environment                []EnvironmentBinding      `json:"environment"`
	Jobs                       []WorkflowJob             `json:"jobs"`
	WorkflowCall               *ReusableWorkflowContract `json:"workflow_call,omitempty"`
	References                 []Reference               `json:"references"`
	Signals                    []StructuralSignal        `json:"signals"`
	Warnings                   []ParseWarning            `json:"warnings"`
	Evidence                   Evidence                  `json:"evidence"`
}

type ComposePort struct {
	Published string   `json:"published,omitempty"`
	Target    string   `json:"target"`
	HostIP    string   `json:"host_ip,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	Evidence  Evidence `json:"evidence"`
}

type ComposeVolume struct {
	Source           string   `json:"source,omitempty"`
	Target           string   `json:"target"`
	Type             string   `json:"type,omitempty"`
	ReadOnly         bool     `json:"read_only"`
	HostBind         bool     `json:"host_bind"`
	WritableHostBind bool     `json:"writable_host_bind"`
	DockerSocket     bool     `json:"docker_socket"`
	Evidence         Evidence `json:"evidence"`
}

type ComposeSecretUse struct {
	Source   string   `json:"source"`
	Target   string   `json:"target,omitempty"`
	Evidence Evidence `json:"evidence"`
}

type ComposeSecret struct {
	Name     string   `json:"name"`
	File     string   `json:"file,omitempty"`
	External bool     `json:"external"`
	Evidence Evidence `json:"evidence"`
}

type NamedValue struct {
	Name     string   `json:"name"`
	Evidence Evidence `json:"evidence"`
}

type FileReference struct {
	Path     string   `json:"path"`
	Evidence Evidence `json:"evidence"`
}

type ComposeService struct {
	Name             string               `json:"name"`
	Environment      []EnvironmentBinding `json:"environment"`
	EnvFiles         []FileReference      `json:"env_files"`
	Secrets          []ComposeSecretUse   `json:"secrets"`
	Ports            []ComposePort        `json:"ports"`
	ExposedPorts     []NamedValue         `json:"exposed_ports"`
	Networks         []NamedValue         `json:"networks"`
	Volumes          []ComposeVolume      `json:"volumes"`
	Privileged       bool                 `json:"privileged"`
	NetworkMode      string               `json:"network_mode,omitempty"`
	HostNetwork      bool                 `json:"host_network"`
	DependsOn        []NamedValue         `json:"depends_on"`
	HasHealthcheck   bool                 `json:"has_healthcheck"`
	Restart          string               `json:"restart,omitempty"`
	Profiles         []NamedValue         `json:"profiles"`
	User             string               `json:"user,omitempty"`
	UserSpecified    bool                 `json:"user_specified"`
	WorkingDirectory string               `json:"working_directory,omitempty"`
	ProductionLike   bool                 `json:"production_like"`
	References       []Reference          `json:"references"`
	Signals          []StructuralSignal   `json:"signals"`
	Evidence         Evidence             `json:"evidence"`
}

type SharedCredential struct {
	Name       string     `json:"name"`
	Services   []string   `json:"services"`
	Confidence Confidence `json:"confidence"`
	Evidence   []Evidence `json:"evidence"`
}

type ComposeProject struct {
	File              string             `json:"file"`
	Services          []ComposeService   `json:"services"`
	Secrets           []ComposeSecret    `json:"secrets"`
	Networks          []NamedValue       `json:"networks"`
	SharedCredentials []SharedCredential `json:"shared_credentials"`
	Warnings          []ParseWarning     `json:"warnings"`
	Evidence          Evidence           `json:"evidence"`
}

type ParsedRepository struct {
	RepositoryRoot   string                    `json:"repository_root"`
	Findings         []Finding                 `json:"findings"`
	Workflows        []Workflow                `json:"workflows"`
	Compose          []ComposeProject          `json:"compose"`
	Warnings         []ParseWarning            `json:"warnings"`
	Ignored          []IgnoredItem             `json:"ignored_items"`
	CompositeActions CompositeActionResolution `json:"composite_actions"`
}

// ActionInputDefinition is one declared `inputs.<name>` entry in a GitHub
// Action's own metadata (action.yml/action.yaml). Composite action inputs
// have no declared type in GitHub's metadata schema, so Default is a plain
// scalar-preserving string pointer, never the typed reusable-workflow
// default model: nil means no default was declared; a non-nil pointer to ""
// means an explicit empty-string default was declared.
type ActionInputDefinition struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required"`
	Default     *string  `json:"default,omitempty"`
	Evidence    Evidence `json:"evidence"`
}

// ActionOutputDefinition is one declared `outputs.<name>` entry. Value is the
// raw declared expression text (e.g. "${{ steps.build.outputs.image }}");
// References captures any expressions found within it.
type ActionOutputDefinition struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Value       string      `json:"value,omitempty"`
	References  []Reference `json:"references"`
	Evidence    Evidence    `json:"evidence"`
}

// ActionInputBinding is one `with.<name>` entry on a composite step's own
// nested `uses:` call to another local action. Value is the raw caller-side
// scalar text; References captures any expressions found within it.
type ActionInputBinding struct {
	Name       string      `json:"name"`
	Value      string      `json:"value,omitempty"`
	References []Reference `json:"references"`
	Evidence   Evidence    `json:"evidence"`
}

// ActionStep is one entry in a composite action's `runs.steps`.
type ActionStep struct {
	ID               string               `json:"id,omitempty"`
	Name             string               `json:"name,omitempty"`
	If               string               `json:"if,omitempty"`
	Action           *ActionReference     `json:"action,omitempty"`
	Run              *ShellCommand        `json:"run,omitempty"`
	Shell            string               `json:"shell,omitempty"`
	WorkingDirectory string               `json:"working_directory,omitempty"`
	With             []ActionInputBinding `json:"with,omitempty"`
	Environment      []EnvironmentBinding `json:"environment,omitempty"`
	ContinueOnError  *bool                `json:"continue_on_error,omitempty"`
	References       []Reference          `json:"references"`
	Evidence         Evidence             `json:"evidence"`
}

// ActionRuns is the `runs:` block of an action's metadata. Using is
// preserved verbatim for every action type (composite, nodeNN, docker, or
// any other literal GitHub accepts); Steps is populated only when
// Using == "composite".
type ActionRuns struct {
	Using    string       `json:"using"`
	Steps    []ActionStep `json:"steps,omitempty"`
	Evidence Evidence     `json:"evidence"`
}

// ActionMetadata is the immutable, scanner-neutral parse of one
// action.yml/action.yaml file. It is not embedded in ParsedRepository by
// CA0: discovery, resolution, and graph wiring for local action references
// are later phases.
type ActionMetadata struct {
	File        string                   `json:"file"`
	Directory   string                   `json:"directory"`
	Name        string                   `json:"name"`
	Description string                   `json:"description,omitempty"`
	Inputs      []ActionInputDefinition  `json:"inputs,omitempty"`
	Outputs     []ActionOutputDefinition `json:"outputs,omitempty"`
	Runs        ActionRuns               `json:"runs"`
	Evidence    Evidence                 `json:"evidence"`
}

// CompositeActionResolutionStatus is the closed set of outcomes for a single
// workflow-step `uses:` action reference, as resolved by
// internal/compositeaction.Resolve.
type CompositeActionResolutionStatus string

const (
	// CompositeActionResolvedLocalComposite means the reference is a safe
	// local directory containing exactly one safe action.yml/action.yaml
	// that parsed successfully and declares runs.using: composite. The
	// canonical ActionMetadata is present in CompositeActionResolution.Actions.
	CompositeActionResolvedLocalComposite CompositeActionResolutionStatus = "resolved_local_composite"
	// CompositeActionOpaqueExternal means the reference is a normal
	// owner/repository action. No filesystem access occurs; existing graph
	// semantics for this call site are unchanged.
	CompositeActionOpaqueExternal CompositeActionResolutionStatus = "opaque_external"
	// CompositeActionOpaqueDocker means the reference is a docker://
	// reference. No filesystem access occurs; existing graph semantics for
	// this call site are unchanged.
	CompositeActionOpaqueDocker CompositeActionResolutionStatus = "opaque_docker"
	// CompositeActionUnsupportedExpression means the raw uses value contains
	// a ${{ ... }} GitHub expression and cannot be statically resolved. No
	// filesystem access occurs and no resolution claim is made.
	CompositeActionUnsupportedExpression CompositeActionResolutionStatus = "unsupported_expression"
	// CompositeActionRejectedPath means the reference looks locally-scoped
	// but is unsafe or structurally invalid: traversal, an absolute path, a
	// drive letter, a UNC path, a backslash, a NUL byte, a query or fragment
	// suffix, a direct action.yml/action.yaml reference, an unsafe
	// (symlink/reparse-point) directory or metadata candidate, or a
	// directory that otherwise fails to resolve safely.
	CompositeActionRejectedPath CompositeActionResolutionStatus = "rejected_path"
	// CompositeActionMetadataMissing means the safe local directory exists
	// but neither action.yml nor action.yaml exists in it.
	CompositeActionMetadataMissing CompositeActionResolutionStatus = "metadata_missing"
	// CompositeActionMetadataAmbiguous means both a safe, regular action.yml
	// and a safe, regular action.yaml exist in the directory. Neither is
	// silently preferred.
	CompositeActionMetadataAmbiguous CompositeActionResolutionStatus = "metadata_ambiguous"
	// CompositeActionMalformedMetadata means exactly one safe metadata file
	// exists but Parser.ParseActionMetadata rejected its YAML or required
	// structure.
	CompositeActionMalformedMetadata CompositeActionResolutionStatus = "malformed_metadata"
	// CompositeActionTargetNotComposite means exactly one safe metadata file
	// exists and parsed successfully, but its runs.using is not "composite"
	// (e.g. a JavaScript or Docker local action). This is a legitimate,
	// common outcome, not a defect.
	CompositeActionTargetNotComposite CompositeActionResolutionStatus = "target_not_composite"
)

// CompositeActionCall is the resolution outcome for one workflow-step
// `uses:` action reference. It never embeds *ActionMetadata: a resolved
// call's canonical action is looked up from CompositeActionResolution.Actions
// by CanonicalDirectory, so call records can never share or mutate a
// canonical action's nested slices through a pointer.
type CompositeActionCall struct {
	CallerWorkflow string `json:"caller_workflow"`
	CallerJobID    string `json:"caller_job_id"`
	// CallerStepIndex is the step's zero-based position within its job's
	// Steps slice — the authoritative identity field, always present and
	// never duplicated. CallerStepID is informational only: a step's own
	// `id:` is optional and, in principle, not guaranteed unique.
	CallerStepIndex int    `json:"caller_step_index"`
	CallerStepID    string `json:"caller_step_id,omitempty"`
	// RawReference preserves the exact, unmodified `uses:` text.
	RawReference string `json:"raw_reference"`
	// CanonicalDirectory is the repository-relative, forward-slash,
	// case-exact directory this reference normalized to. It is empty for
	// OpaqueExternal, OpaqueDocker, and UnsupportedExpression (the reference
	// was never attempted as a local path) and for a RejectedPath caused by
	// string-level grammar rejection before any filesystem lookup was
	// attempted. It is populated for MetadataMissing, MetadataAmbiguous,
	// MalformedMetadata, TargetNotComposite, and ResolvedLocalComposite, and
	// may also be populated for a RejectedPath whose normalized path passed
	// grammar validation but was rejected at the filesystem-confinement
	// layer (e.g. a symlinked directory component or an escape outside the
	// repository root).
	CanonicalDirectory string `json:"canonical_directory,omitempty"`
	// MetadataFile is "action.yml" or "action.yaml" — whichever single safe
	// candidate was selected — populated only for MalformedMetadata,
	// TargetNotComposite, and ResolvedLocalComposite. It is evidence, never
	// part of any identity.
	MetadataFile string                          `json:"metadata_file,omitempty"`
	Status       CompositeActionResolutionStatus `json:"status"`
	Reason       string                          `json:"reason,omitempty"`
	Evidence     Evidence                        `json:"evidence"`
}

// CompositeActionResolution is the deterministic, immutable output of
// internal/compositeaction.Resolve. Actions holds at most one ActionMetadata
// value per canonical directory; Calls holds one record per workflow-step
// action reference and references its action only through
// CanonicalDirectory/MetadataFile, never by pointer, so mutating one
// resolution result's slices can never affect a separately produced result.
type CompositeActionResolution struct {
	Actions []ActionMetadata      `json:"actions"`
	Calls   []CompositeActionCall `json:"calls"`
}
