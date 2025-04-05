package controllers

import (
	"net/http"
	"os/exec"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	falcoCmd     *exec.Cmd
	falcoRunning bool
	falcoMutex   sync.Mutex
)

func StartFalcoInBackground(c *gin.Context) {
	falcoMutex.Lock()
	defer falcoMutex.Unlock()

	if falcoRunning {
		c.JSON(http.StatusOK, gin.H{"status": "Falco is already running"})
		return
	}

	scriptPath := "./falco/falco.sh"
	cmd := exec.Command("sudo", "bash", scriptPath)
	//cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // Keep process detached
	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start Falco: " + err.Error()})
		return
	}
	falcoCmd = cmd
	falcoRunning = true
	c.JSON(http.StatusOK, gin.H{"message": "Falco started successfully"})
}

func StopFalco(c *gin.Context) {
	falcoMutex.Lock()
	defer falcoMutex.Unlock()

	if !falcoRunning {
		c.JSON(http.StatusOK, gin.H{"status": "Falco is not running"})
		return
	}

	// Find the Falco process and kill it
	err := exec.Command("pkill", "-f", "falco").Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to stop Falco: " + err.Error()})
		return
	}

	falcoRunning = false
	falcoCmd = nil
	c.JSON(http.StatusOK, gin.H{"status": "Falco stopped successfully"})
}
