package buildinfo

import "strings"

var (
	Version = "dev"
	Commit  = "none"
	Branch  = ""
	Date    = ""
)

func String() string {
	version := strings.TrimSpace(Version)
	if version == "" {
		version = "dev"
	}

	metadata := make([]string, 0, 3)

	commit := strings.TrimSpace(Commit)
	if commit != "" && commit != "none" {
		metadata = append(metadata, "commit="+commit)
	}

	branch := strings.TrimSpace(Branch)
	if branch != "" {
		metadata = append(metadata, "branch="+branch)
	}

	date := strings.TrimSpace(Date)
	if date != "" {
		metadata = append(metadata, "built="+date)
	}

	if len(metadata) == 0 {
		return version
	}

	return version + " (" + strings.Join(metadata, ", ") + ")"
}
