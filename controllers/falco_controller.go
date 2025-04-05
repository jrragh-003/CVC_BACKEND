package controllers

import (
	"CVC_ragh/config"
	"CVC_ragh/models"
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Prometheus Metrics
var (
	// Existing Metrics
	activeRuleAlerts = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "container_security_rule_alerts_active",
			Help: "Number of currently active security alerts by rule",
		},
		[]string{"rule_name"},
	)
	ruleAlertsByCategory = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_security_alerts_by_category_total",
			Help: "Number of security alerts grouped by category",
		},
		[]string{"priority"},
	)

	ruleAlertsByImage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "container_security_alerts_by_image_total",
			Help: "Number of security alerts grouped by container image",
		},
		[]string{"image", "container_name"},
	)

	containerViolationsCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "container_security_violations_count",
			Help: "Number of security violations per container",
		},
		[]string{"container_name", "rule_name"},
	)
)

func init() {
	prometheus.MustRegister(
		activeRuleAlerts, ruleAlertsByImage, ruleAlertsByCategory, containerViolationsCount)

}

// FalcoAlert represents the structure of a Falco alert log
type FalcoAlert struct {
	Rule         string `json:"rule"`
	Priority     string `json:"priority"`
	Output       string `json:"output"`
	Time         string `json:"time"`
	Source       string `json:"source"`
	Hostname     string `json:"hostname"`
	Category     string `json:"category"` // Add this field
	OutputFields struct {
		ContainerID   string `json:"container.id"`
		ContainerName string `json:"container.name"`
		ProcessName   string `json:"proc.name"`
	} `json:"output_fields"`
}

// FalcoWebhookHandler processes incoming alerts and updates Prometheus metrics
func FalcoWebhookHandler(c *gin.Context) {
	var falcoEvent FalcoAlert

	// Bind JSON payload to FalcoAlert struct
	if err := c.BindJSON(&falcoEvent); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	// Log received alert
	fmt.Println("🔥 Received Falco Alert:")
	fmt.Printf("  🔥 Rule: %s\n", falcoEvent.Rule)
	fmt.Printf("  🚨 Priority: %s\n", falcoEvent.Priority)
	fmt.Printf("  📝 Output: %s\n", falcoEvent.Output)

	containerName := falcoEvent.OutputFields.ContainerName
	imageName, err := GetImageByContainerName(falcoEvent.OutputFields.ContainerName)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Here is the Image Name:", imageName)
	}

	activeRuleAlerts.WithLabelValues(falcoEvent.Rule).Inc()
	ruleAlertsByImage.WithLabelValues(imageName, containerName).Inc()
	ruleAlertsByCategory.WithLabelValues(falcoEvent.Priority).Inc()
	containerViolationsCount.WithLabelValues(containerName, falcoEvent.Rule).Inc()

	c.JSON(http.StatusOK, gin.H{"message": "Falco alert processed successfully"})

}

// PrometheusMetricsHandler exposes metrics for Prometheus
func PrometheusMetricsHandler(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}

func GetImageByContainerName(containerName string) (string, error) {
	collection := config.GetDB().Collection("containers") // Get MongoDB collection

	// Define query filter
	filter := bson.M{"name": containerName}

	// Define a variable of type models.Container
	var container models.Container

	// Execute the query
	err := collection.FindOne(context.Background(), filter).Decode(&container)
	if err == mongo.ErrNoDocuments {
		return "", fmt.Errorf("no container found with name: %s", containerName)
	} else if err != nil {
		return "", fmt.Errorf("database error: %v", err)
	}

	return container.BaseImage, nil
}
