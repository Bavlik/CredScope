package domain

// ReferenceKind identifies a safe expression reference, never its resolved value.
type ReferenceKind string

const (
	ReferenceSecret          ReferenceKind = "secret"
	ReferenceEnvironment     ReferenceKind = "environment"
	ReferenceGitHubContext   ReferenceKind = "github_context"
	ReferenceComposeVariable ReferenceKind = "compose_variable"
	ReferenceComposeSecret   ReferenceKind = "compose_secret"
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
	ID                      string                   `json:"id"`
	Name                    string                   `json:"name,omitempty"`
	Needs                   []string                 `json:"needs"`
	Permissions             []Permission             `json:"permissions"`
	Environment             []EnvironmentBinding     `json:"environment"`
	EnvironmentName         string                   `json:"environment_name,omitempty"`
	EnvironmentEvidence     *Evidence                `json:"environment_evidence,omitempty"`
	ReusableWorkflow        *ActionReference         `json:"reusable_workflow,omitempty"`
	ReusableResolved        bool                     `json:"reusable_resolved"`
	ReusableWorkflowInputs  []ReusableWorkflowInput  `json:"reusable_workflow_inputs,omitempty"`
	ReusableWorkflowSecrets []ReusableWorkflowSecret `json:"reusable_workflow_secrets,omitempty"`
	ReusableSecretsInherit  bool                     `json:"reusable_secrets_inherit,omitempty"`
	Steps                   []WorkflowStep           `json:"steps"`
	Outputs                 []WorkflowOutput         `json:"outputs"`
	References              []Reference              `json:"references"`
	Signals                 []StructuralSignal       `json:"signals"`
	Evidence                Evidence                 `json:"evidence"`
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
	RepositoryRoot string           `json:"repository_root"`
	Findings       []Finding        `json:"findings"`
	Workflows      []Workflow       `json:"workflows"`
	Compose        []ComposeProject `json:"compose"`
	Warnings       []ParseWarning   `json:"warnings"`
	Ignored        []IgnoredItem    `json:"ignored_items"`
}
