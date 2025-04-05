package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// DockerImage represents a Docker image
type Image struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Label      string             `bson:"label" json:"label"`
	Repository string             `bson:"repository" json:"repository"`
	Tag        string             `bson:"tag" json:"tag"`
	CreateddAt int64              `bson:"pulled_at" json:"created_at"`
	User       string             `bson:"user" json:"user"`
}

type TrivyScan struct {
	ID            primitive.ObjectID `bson:"_id,omitempty"`  // MongoDB Object ID
	ImageName     string             `bson:"image_name"`     // Name of the scanned image
	SeverityCount map[string]int     `bson:"severity_count"` // Map to store severity counts
	ScanTime      time.Time          `bson:"scan_time"`      // Time of the scan
}

type VulnerabilitySummary struct {
	ID           string
	PackageName  string
	InstalledVer string
	FixedVersion string
	Severity     string
	Title        string
}

type SummaryReport struct {
	ImageName     string
	User          string
	ScanTime      string
	SeverityCount map[string]int
	TopVulns      []string
}
