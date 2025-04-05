package main

import (
	"CVC_ragh/config"
	"CVC_ragh/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Register user routes
	config.InitDB()
	routes.RegisterUserRoutes(r)
	routes.RegisterContainerRoutes(r)
	routes.RegisterScanningRoutes(r)
	routes.RegisterDynamicScanningRoutes(r)
	routes.RegisterFalcoWebHook(r)
	r.Run(":4000") // Start server on port 5000
}
