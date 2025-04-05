package routes

import (
	"CVC_ragh/controllers"

	"github.com/gin-gonic/gin"
)

func RegisterContainerRoutes(router *gin.Engine) {
	containerGroup := router.Group("/api/container")
	{
		containerGroup.POST("/createContainer/:imageName", controllers.CreateContainerFromImage)
		containerGroup.POST("/startContainer/:name", controllers.StartContainer)     // Start a new container
		containerGroup.POST("/stopContainer/:name", controllers.StopContainer)       // Stop a container
		containerGroup.DELETE("/deleteContainer/:name", controllers.DeleteContainer) // Delete a container
		containerGroup.GET("/getContainerDetails/:name", controllers.GetContainerDetails)
	}
}
