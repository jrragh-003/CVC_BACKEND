package routes

import (
	"CVC_ragh/controllers"

	"github.com/gin-gonic/gin"
)

func RegisterScanningRoutes(router *gin.Engine) {
	scanGroup := router.Group("/api/static-scan")
	{
		scanGroup.POST("/:imageName", controllers.ScanImage) // Scan Docker image
	}
}
