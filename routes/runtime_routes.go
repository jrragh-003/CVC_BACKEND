package routes

import (
	"CVC_ragh/controllers"

	"github.com/gin-gonic/gin"
)

func RegisterDynamicScanningRoutes(router *gin.Engine) {
	dynamicScanGroup := router.Group("/api/dynamic-scan")
	{
		// Fetch Falco logs
		dynamicScanGroup.GET("/logs", controllers.StartFalcoInBackground)
		dynamicScanGroup.POST("/stop-falco", controllers.StopFalco) // Uncomment if needed

	}
}

func RegisterFalcoWebHook(router *gin.Engine) {
	falcoWebHookGroup := router.Group("/api")
	{
		falcoWebHookGroup.POST("/falco-webhook", controllers.FalcoWebhookHandler)
		router.GET("/metrics", controllers.PrometheusMetricsHandler)
	}
}
