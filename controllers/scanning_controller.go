package controllers

import (
	"CVC_ragh/config"
	"CVC_ragh/models"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/jung-kurt/gofpdf"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TrivyScanResult struct {
	ImageName     string         `json:"image_name"`
	SeverityCount map[string]int `json:"severity_count"`
	ScanTime      string         `json:"scan_time"`
}

// Main Scan Handler
func ScanImage(c *gin.Context) {
	imageName := c.Param("imageName")
	user := c.Query("user")

	if imageName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Image name is required"})
		return
	}

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to init Docker client", "details": err.Error()})
		return
	}
	cli.NegotiateAPIVersion(context.Background())

	_, _, err = cli.ImageInspectWithRaw(context.Background(), imageName)
	if err != nil {
		fmt.Println("Pulling image from Docker Hub...")
		out, pullErr := cli.ImagePull(context.Background(), imageName, types.ImagePullOptions{})
		if pullErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to pull image", "details": pullErr.Error()})
			return
		}
		defer out.Close()
	}

	cmd := exec.Command("trivy", "image", "--quiet", "--format", "json", imageName)
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Trivy scan failed", "details": err.Error()})
		return
	}

	var trivyResults map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &trivyResults); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse scan results"})
		return
	}

	severityCount := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	if results, ok := trivyResults["Results"].([]interface{}); ok {
		for _, result := range results {
			if resultMap, ok := result.(map[string]interface{}); ok {
				if vulnerabilities, ok := resultMap["Vulnerabilities"].([]interface{}); ok {
					for _, vuln := range vulnerabilities {
						if vulnMap, ok := vuln.(map[string]interface{}); ok {
							if severity, ok := vulnMap["Severity"].(string); ok {
								if _, exists := severityCount[severity]; exists {
									severityCount[severity]++
								}
							}
						}
					}
				}
			}
		}
	}

	scanResult := TrivyScanResult{
		ImageName:     imageName,
		SeverityCount: severityCount,
		ScanTime:      time.Now().UTC().Format(time.RFC3339),
	}

	if err := SaveTrivyScan(scanResult.ImageName, scanResult.SeverityCount); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save scan result", "details": err.Error()})
		return
	}

	pdfFileName := fmt.Sprintf("trivy_report_%s_%d.pdf", imageName, time.Now().Unix())
	pdfFilePath := filepath.Join("pdf_reports", pdfFileName)

	if err := GenerateUserFriendlyPDF(trivyResults, scanResult, pdfFilePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate PDF"})
		return
	}

	imageDetails, _, err := cli.ImageInspectWithRaw(context.Background(), imageName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to inspect image", "details": err.Error()})
		return
	}

	repository, tag := parseRepositoryAndTag(imageName)

	err = SaveImageDetails(repository, tag, imageDetails.Created, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save image details", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, scanResult)
}

// ------------------ Helpers ------------------

func parseRepositoryAndTag(image string) (string, string) {
	tag := "latest"
	lastColon := strings.LastIndex(image, ":")
	if lastColon > -1 && !strings.Contains(image[lastColon:], "/") {
		return image[:lastColon], image[lastColon+1:]
	}
	return image, tag
}

func SaveImageDetails(repository, tag string, created string, user string) error {
	createdTime, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return fmt.Errorf("parse creation time failed: %v", err)
	}

	collection := config.GetDB().Collection("images")
	image := models.Image{
		ID:         primitive.NewObjectID(),
		Label:      fmt.Sprintf("%s:%s", repository, tag),
		Repository: repository,
		Tag:        tag,
		CreateddAt: createdTime.Unix(),
		User:       user,
	}

	_, err = collection.InsertOne(context.Background(), image)
	return err
}

func SaveTrivyScan(imageName string, severityCount map[string]int) error {
	collection := config.GetDB().Collection("trivy_scans")
	scan := models.TrivyScan{
		ImageName:     imageName,
		SeverityCount: severityCount,
		ScanTime:      time.Now(),
	}
	_, err := collection.InsertOne(context.Background(), scan)
	return err
}

// ----------------- PDF Report -------------------

func GenerateUserFriendlyPDF(scanResult map[string]interface{}, summary TrivyScanResult, filePath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(10, 10, 10)
	pdf.AddPage()

	// Title
	pdf.SetFont("Arial", "B", 20)
	pdf.Cell(190, 10, "Trivy Vulnerability Scan Report")
	pdf.Ln(12)
	// Metadata
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(190, 8, fmt.Sprintf("Image: %s", summary.ImageName))
	pdf.Ln(6)
	//pdf.Cell(190, 8, fmt.Sprintf("Scanned By: %s"))
	pdf.Ln(6)
	pdf.Cell(190, 8, fmt.Sprintf("Scan Time: %s", summary.ScanTime))
	pdf.Ln(12)

	// Severity Summary
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(190, 10, "Vulnerability Severity Summary")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 12)
	pdf.CellFormat(60, 8, "Severity", "1", 0, "", false, 0, "")
	pdf.CellFormat(60, 8, "Count", "1", 1, "", false, 0, "")

	for severity, count := range summary.SeverityCount {
		pdf.CellFormat(60, 8, severity, "1", 0, "", false, 0, "")
		pdf.CellFormat(60, 8, fmt.Sprintf("%d", count), "1", 1, "", false, 0, "")
	}
	pdf.Ln(10)

	// Top Vulnerabilities
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(190, 10, "Sample Vulnerabilities")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 11)

	// Extract and list a few vulnerabilities
	if results, ok := scanResult["Results"].([]interface{}); ok {
		for _, result := range results {
			if resultMap, ok := result.(map[string]interface{}); ok {
				if vulns, ok := resultMap["Vulnerabilities"].([]interface{}); ok {
					count := 0
					for _, v := range vulns {
						if vmap, ok := v.(map[string]interface{}); ok && count < 5 {
							title := vmap["Title"]
							cve := vmap["VulnerabilityID"]
							severity := vmap["Severity"]
							desc := vmap["Description"]
							fixedVersion := vmap["FixedVersion"]

							pdf.SetFont("Arial", "B", 11)
							pdf.Cell(190, 8, fmt.Sprintf("%s [%s]", title, severity))
							pdf.Ln(6)

							pdf.SetFont("Arial", "", 11)
							pdf.MultiCell(0, 6, fmt.Sprintf(
								"CVE: %s\n%s\n Fix Available: %s",
								cve,
								desc,
								fixedVersion,
							), "", "", false)
							pdf.Ln(4)

							count++
						}
					}
				}
			}
		}
	}

	// Save the file
	return pdf.OutputFileAndClose(filePath)
}
