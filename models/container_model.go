package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Container represents a container's metadata and security status
type Container struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ContainerID string             `bson:"container_id" json:"container_id"`
	Name        string             `bson:"name" json:"name"`
	BaseImage   string             `bson:"image" json:"image"`
	Status      string             `bson:"status" json:"status"`
	CreatedAt   time.Time          `bson:"created_at"`
	User        string             `bson:"user" json:"user"`
}
