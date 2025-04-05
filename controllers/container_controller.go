package controllers

import (
	"CVC_ragh/models"
	"context"
	"fmt"
	"net/http"
	"time"

	"CVC_ragh/config"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

func CreateContainerFromImage(c *gin.Context) {
	imageName := c.Param("imageName") // Get image name from request

	fmt.Println("🚀 Creating container from image:", imageName)

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Docker connection failed", "details": err.Error()})
		return
	}
	defer cli.Close()

	fmt.Println("✅ Docker client initialized successfully!")

	// Create a new container (without manually setting a name)
	resp, err := cli.ContainerCreate(
		context.Background(),
		&container.Config{
			Image: imageName,
			Cmd:   []string{"tail", "-f", "/dev/null"}, // Keep container idle
		},
		nil, nil, nil, "",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create container", "details": err.Error()})
		return
	}

	fmt.Println("✅ Container created successfully! ID:", resp.ID)

	// Get the default name assigned by Docker
	containerJSON, err := cli.ContainerInspect(context.Background(), resp.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to inspect container", "details": err.Error()})
		return
	}
	containerName := containerJSON.Name // Docker includes a leading "/", remove it
	if len(containerName) > 0 {
		containerName = containerName[1:]
	}

	fmt.Println("📝 Assigned container name:", containerName)

	// Store container details in the database
	err = StoreContainerInDB(resp.ID, imageName, containerName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save container info", "details": err.Error()})
		return
	}

	fmt.Println("✅ Container details stored in database!")

	// Respond with container ID & name
	c.JSON(http.StatusOK, gin.H{
		"message":        "Container created successfully",
		"container_id":   resp.ID,
		"container_name": containerName,
	})
}

// StartContainer starts a new container and updates its status in the database
func StartContainer(c *gin.Context) {
	// Get container ID from URL params
	containerName := c.Param("name")

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Docker client error"})
		return
	}
	defer cli.Close()

	ctx := context.Background()

	// Check if the container exists and is stopped
	containerJSON, err := cli.ContainerInspect(ctx, containerName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to inspect container"})
		return
	}

	// If the container is already running, notify the user
	if containerJSON.State.Running {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Container is already running"})
		return
	}

	// Start the container
	if err := cli.ContainerStart(ctx, containerName, types.ContainerStartOptions{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start container"})
		return
	}

	// Update the container status in the database to "running"
	err = UpdateContainerStatusInDB(containerName, "running")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update container status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Container started", "container_id": containerName})
}

// StopContainer stops a running container
func StopContainer(c *gin.Context) {
	containerName := c.Param("name")

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Docker client error"})
		return
	}
	defer cli.Close()

	ctx := context.Background()
	if err := cli.ContainerStop(ctx, containerName, container.StopOptions{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to stop container"})
		return
	}
	err = UpdateContainerStatusInDB(containerName, "stopped")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update container status"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Container stopped", "container_id": containerName})
}

// DeleteContainer removes a container and updates its status in the database
func DeleteContainer(c *gin.Context) {
	containerName := c.Param("name") // Ensure this matches the route parameter

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Docker client error"})
		return
	}
	defer cli.Close()

	ctx := context.Background()

	// Attempt to stop the container (ignore errors if already stopped or not found)
	_ = cli.ContainerStop(ctx, containerName, container.StopOptions{})

	// Remove the container
	if err := cli.ContainerRemove(ctx, containerName, types.ContainerRemoveOptions{Force: true}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete container"})
		return
	}

	// Update the container status in the database
	collection := config.GetDB().Collection("containers")

	// Define the filter and delete operation
	filter := bson.M{"name": containerName}
	_, err = collection.DeleteOne(context.Background(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete container from DB"})
		return
	}

	// Respond to the client
	c.JSON(http.StatusOK, gin.H{"message": "Container deleted successfully", "container_name": containerName})
}

func GetContainerDetails(c *gin.Context) {
	containerName := c.Param("name")

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create Docker client"})
		return
	}

	containerJSON, err := cli.ContainerInspect(context.Background(), containerName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Container %s not found", containerName)})
		return
	}

	// Prepare response data
	containerDetails := gin.H{
		"ID":      containerJSON.ID,
		"Image":   containerJSON.Config.Image,
		"Created": containerJSON.Created,
		"State":   containerJSON.State.Status,
	}

	c.JSON(http.StatusOK, containerDetails)
}

func StoreContainerInDB(containerID, imageName, containerName string) error {
	// Create a container object
	container := models.Container{
		ContainerID: containerID,
		Name:        containerName,
		Status:      "created", // Set initial status as created
		BaseImage:   imageName,
		CreatedAt:   time.Now(),
	}

	// Get the MongoDB collection
	collection := config.GetDB().Collection("containers")

	// Insert the container into the database
	_, err := collection.InsertOne(context.Background(), container)
	if err != nil {
		return fmt.Errorf("failed to insert container in DB: %v", err)
	}

	return nil
}

func UpdateContainerStatusInDB(containerName, status string) error {
	// Get the MongoDB collection
	collection := config.GetDB().Collection("containers")

	// Define the filter and update data
	filter := bson.M{"name": containerName}
	update := bson.M{"$set": bson.M{"status": status}}

	// Update the container status in the DB
	_, err := collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return fmt.Errorf("failed to update container status in DB: %v", err)
	}

	return nil
}
