package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID              primitive.ObjectID `bson:"_id,omitempty"`
	Username        string             `json:"username" bson:"username"`
	Password        string             `json:"password" bson:"password"`
	Github_username string             `json:"git_username" bson:"git_username"`
	PDFUuid         []string           `json:"pdf_id" bson:"pdf_id"`
}
