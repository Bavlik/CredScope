package domain

const RuleCatalogVersion = "v2"

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type PathNode struct {
	ID         string     `json:"id"`
	Type       NodeType   `json:"type"`
	Label      string     `json:"label"`
	Location   *Location  `json:"location,omitempty"`
	Confidence Confidence `json:"confidence"`
}

type PathEdge struct {
	ID           string       `json:"id"`
	From         string       `json:"from"`
	To           string       `json:"to"`
	Relationship EdgeType     `json:"relationship"`
	EvidenceKind EvidenceKind `json:"evidence_kind"`
	Evidence     []Evidence   `json:"evidence,omitempty"`
	Confidence   Confidence   `json:"confidence"`
}

type EvidencePath struct {
	ID           string       `json:"id"`
	CredentialID string       `json:"credential_id"`
	Nodes        []PathNode   `json:"nodes"`
	Edges        []PathEdge   `json:"edges"`
	Confidence   Confidence   `json:"confidence"`
	EvidenceKind EvidenceKind `json:"evidence_kind"`
	Truncated    bool         `json:"truncated,omitempty"`
}

type CredentialSubject struct {
	ID                       string         `json:"id"`
	Label                    string         `json:"label"`
	Type                     string         `json:"type,omitempty"`
	Fingerprints             []string       `json:"fingerprints,omitempty"`
	Classification           Classification `json:"classification"`
	ClassificationConfidence Confidence     `json:"classification_confidence"`
	ClassificationReason     string         `json:"classification_reason"`
	ClassificationSource     string         `json:"classification_source"`
	ExpectedSecret           bool           `json:"expected_secret"`
	RotationApplicable       bool           `json:"rotation_remediation_applicable"`
	TestFixtureCandidate     bool           `json:"test_fixture_candidate"`
}

type RuleMatch struct {
	RuleID          string     `json:"rule_id"`
	Title           string     `json:"title"`
	Category        string     `json:"category"`
	Severity        Severity   `json:"severity"`
	Confidence      Confidence `json:"confidence"`
	Evidence        []Evidence `json:"evidence"`
	AffectedNodeIDs []string   `json:"affected_node_ids"`
	PathIDs         []string   `json:"path_ids"`
	RemediationID   string     `json:"remediation_id"`
}

type ScoreAdjustment struct {
	Kind             string `json:"kind"`
	Percent          int    `json:"percent"`
	Description      string `json:"description"`
	RiskOrConfidence string `json:"risk_or_confidence"`
	ProfileChanged   bool   `json:"profile_changed"`
}

type ScoreContribution struct {
	RuleID            string            `json:"rule_id"`
	Description       string            `json:"description"`
	BaseWeight        int               `json:"base_weight"`
	Adjustments       []ScoreAdjustment `json:"adjustments"`
	AdjustedWeight    int               `json:"adjusted_weight"`
	ConfidenceWeight  int               `json:"confidence_weight_percent"`
	FinalContribution int               `json:"final_contribution"`
	Confidence        Confidence        `json:"confidence"`
	ConditionStatus   string            `json:"condition_status"`
	RiskOrConfidence  string            `json:"risk_or_confidence"`
	ProfileChanged    bool              `json:"profile_changed"`
	Evidence          []Evidence        `json:"evidence"`
}

type ConfidenceSummary struct {
	Confirmed int        `json:"confirmed"`
	High      int        `json:"high"`
	Medium    int        `json:"medium"`
	Low       int        `json:"low"`
	Unknown   int        `json:"unknown"`
	Overall   Confidence `json:"overall"`
}

type ReachableCounts struct {
	Workflows       int `json:"workflows"`
	Jobs            int `json:"jobs"`
	Services        int `json:"services"`
	Permissions     int `json:"permissions"`
	Environments    int `json:"environments"`
	ExternalActions int `json:"external_actions"`
	PublishedPorts  int `json:"published_ports"`
	VolumeMounts    int `json:"volume_mounts"`
}

type RemediationResult struct {
	ID                string     `json:"id"`
	Title             string     `json:"title"`
	Why               string     `json:"why"`
	TriggeringRuleIDs []string   `json:"triggering_rule_ids"`
	EvidencePathIDs   []string   `json:"evidence_path_ids"`
	AffectedLocations []Location `json:"affected_locations"`
	Confidence        Confidence `json:"confidence"`
	SuggestedAction   string     `json:"suggested_action"`
	Priority          int        `json:"priority"`
}

type CredentialAnalysis struct {
	Credential         CredentialSubject   `json:"credential"`
	Score              int                 `json:"score"`
	Severity           Severity            `json:"severity"`
	PolicyVersion      string              `json:"policy_version"`
	RuleCatalogVersion string              `json:"rule_catalog_version"`
	MatchedRules       []RuleMatch         `json:"matched_rules"`
	Contributions      []ScoreContribution `json:"contributions"`
	Confidence         ConfidenceSummary   `json:"confidence"`
	Reachable          ReachableCounts     `json:"reachable"`
	EvidencePaths      []EvidencePath      `json:"evidence_paths"`
	Warnings           []string            `json:"warnings"`
	RemediationIDs     []string            `json:"remediation_ids"`
	Remediations       []RemediationResult `json:"remediations"`
}

type AnalysisResult struct {
	PolicyVersion      string               `json:"policy_version"`
	RuleCatalogVersion string               `json:"rule_catalog_version"`
	Graph              Graph                `json:"graph"`
	Credentials        []CredentialAnalysis `json:"credentials"`
	Warnings           []string             `json:"warnings"`
	Profile            ProfileSelection     `json:"profile"`
	IgnoredItems       []IgnoredItem        `json:"ignored_items"`
	IgnoredCount       int                  `json:"ignored_count"`
}
