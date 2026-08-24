package contract

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Campaign describes the authorization, threat model, environment, and
// concrete success condition for one research campaign.
type Campaign struct {
	Version       string        `yaml:"version"`
	Name          string        `yaml:"name"`
	Target        Target        `yaml:"target"`
	Authorization Authorization `yaml:"authorization"`
	Attacker      Attacker      `yaml:"attacker"`
	Environment   Environment   `yaml:"environment"`
	Success       Success       `yaml:"success"`
	Discovery     Discovery     `yaml:"discovery"`
}

type Target struct {
	Name           string `yaml:"name"`
	SourceSnapshot string `yaml:"source_snapshot"`
	SourcePath     string `yaml:"source_path"`
}

type Authorization struct {
	Owner             string `yaml:"owner"`
	Scope             string `yaml:"scope"`
	WrittenPermission bool   `yaml:"written_permission"`
	Evidence          string `yaml:"evidence"`
}

type Attacker struct {
	StartingPrivilege string   `yaml:"starting_privilege"`
	Capabilities      []string `yaml:"capabilities"`
	Excluded          []string `yaml:"excluded"`
}

type Environment struct {
	Deployment    string `yaml:"deployment"`
	Network       string `yaml:"network"`
	Isolation     string `yaml:"isolation"`
	SyntheticData bool   `yaml:"synthetic_data"`
	Disposable    bool   `yaml:"disposable"`
}

type Success struct {
	Impact   string   `yaml:"impact"`
	Evidence []string `yaml:"evidence"`
}

type Discovery struct {
	SourceFirst        bool `yaml:"source_first"`
	HistoryRestricted  bool `yaml:"history_restricted"`
	InternetRestricted bool `yaml:"internet_restricted"`
}

func Load(path string) (Campaign, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Campaign{}, fmt.Errorf("read campaign: %w", err)
	}
	var campaign Campaign
	if err := yaml.Unmarshal(data, &campaign); err != nil {
		return Campaign{}, fmt.Errorf("parse campaign: %w", err)
	}
	return campaign, nil
}

func (c Campaign) Validate() error {
	var problems []string
	require := func(condition bool, field, message string) {
		if !condition {
			problems = append(problems, field+": "+message)
		}
	}

	require(strings.TrimSpace(c.Version) != "", "version", "is required")
	require(strings.TrimSpace(c.Name) != "", "name", "is required")
	require(strings.TrimSpace(c.Target.Name) != "", "target.name", "is required")
	require(strings.TrimSpace(c.Target.SourceSnapshot) != "", "target.source_snapshot", "is required")
	require(strings.TrimSpace(c.Target.SourcePath) != "", "target.source_path", "is required")
	require(strings.TrimSpace(c.Authorization.Owner) != "", "authorization.owner", "is required")
	require(strings.TrimSpace(c.Authorization.Scope) != "", "authorization.scope", "is required")
	require(c.Authorization.WrittenPermission, "authorization.written_permission", "must be true")
	require(strings.TrimSpace(c.Authorization.Evidence) != "", "authorization.evidence", "is required")
	require(strings.TrimSpace(c.Attacker.StartingPrivilege) != "", "attacker.starting_privilege", "is required")
	require(len(c.Attacker.Capabilities) > 0, "attacker.capabilities", "must contain at least one capability")
	require(strings.TrimSpace(c.Environment.Deployment) != "", "environment.deployment", "is required")
	require(c.Environment.Network == "denied" || c.Environment.Network == "allowlisted", "environment.network", "must be denied or allowlisted")
	require(strings.TrimSpace(c.Environment.Isolation) != "", "environment.isolation", "is required")
	require(c.Environment.SyntheticData, "environment.synthetic_data", "must be true")
	require(c.Environment.Disposable, "environment.disposable", "must be true")
	require(strings.TrimSpace(c.Success.Impact) != "", "success.impact", "is required")
	require(len(c.Success.Evidence) > 0, "success.evidence", "must contain at least one artifact")
	require(c.Discovery.SourceFirst, "discovery.source_first", "must be true")
	require(c.Discovery.HistoryRestricted, "discovery.history_restricted", "must be true")
	require(c.Discovery.InternetRestricted, "discovery.internet_restricted", "must be true")

	if len(problems) > 0 {
		return errors.New("invalid campaign contract:\n- " + strings.Join(problems, "\n- "))
	}
	return nil
}

func Template(name string) Campaign {
	return Campaign{
		Version: "v1",
		Name:    name,
		Target: Target{
			Name:           "replace-with-authorized-local-target",
			SourceSnapshot: "sha256:replace-with-source-digest",
			SourcePath:     "./target",
		},
		Authorization: Authorization{
			Owner:             "replace-with-owner",
			Scope:             "local snapshot only",
			WrittenPermission: true,
			Evidence:          "replace-with-permission-record",
		},
		Attacker: Attacker{
			StartingPrivilege: "unauthenticated",
			Capabilities:      []string{"send protocol requests to local fixture"},
			Excluded:          []string{"real credentials", "real user data", "external network"},
		},
		Environment: Environment{
			Deployment:    "disposable local container",
			Network:       "denied",
			Isolation:     "rootless container with read-only source mount",
			SyntheticData: true,
			Disposable:    true,
		},
		Success: Success{
			Impact:   "replace-with-concrete-impact",
			Evidence: []string{"reproduction test", "clean-run log", "source snapshot digest"},
		},
		Discovery: Discovery{SourceFirst: true, HistoryRestricted: true, InternetRestricted: true},
	}
}
