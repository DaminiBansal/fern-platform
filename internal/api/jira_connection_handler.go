package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/guidewire-oss/fern-platform/internal/domains/integrations"
	projectsApp "github.com/guidewire-oss/fern-platform/internal/domains/projects/application"
	projectsDomain "github.com/guidewire-oss/fern-platform/internal/domains/projects/domain"
)

// JiraConnectionHandler handles JIRA connection HTTP requests
type JiraConnectionHandler struct {
	*BaseHandler
	jiraService    *integrations.JiraConnectionService
	projectService *projectsApp.ProjectService
}

// NewJiraConnectionHandler creates a new JIRA connection handler
func NewJiraConnectionHandler(
	baseHandler *BaseHandler,
	jiraService *integrations.JiraConnectionService,
	projectService *projectsApp.ProjectService,
) *JiraConnectionHandler {
	return &JiraConnectionHandler{
		BaseHandler:    baseHandler,
		jiraService:    jiraService,
		projectService: projectService,
	}
}

// CreateJiraConnectionRequest represents the request to create a JIRA connection
type CreateJiraConnectionRequest struct {
	Name               string `json:"name" binding:"required"`
	JiraURL            string `json:"jiraUrl" binding:"required"`
	AuthenticationType string `json:"authenticationType" binding:"required"`
	ProjectKey         string `json:"projectKey" binding:"required"`
	Username           string `json:"username"`
	Credential         string `json:"credential" binding:"required"`
}

// UpdateJiraConnectionRequest represents the request to update a JIRA connection
type UpdateJiraConnectionRequest struct {
	Name       string `json:"name"`
	JiraURL    string `json:"jiraUrl"`
	ProjectKey string `json:"projectKey"`
}

// UpdateJiraCredentialsRequest represents the request to update JIRA credentials
type UpdateJiraCredentialsRequest struct {
	AuthenticationType string `json:"authenticationType" binding:"required"`
	Username           string `json:"username"`
	Credential         string `json:"credential" binding:"required"`
}

// JiraConnectionResponse represents a JIRA connection response
type JiraConnectionResponse struct {
	ID                 string  `json:"id"`
	ProjectID          string  `json:"projectId"`
	Name               string  `json:"name"`
	JiraURL            string  `json:"jiraUrl"`
	AuthenticationType string  `json:"authenticationType"`
	ProjectKey         string  `json:"projectKey"`
	Username           string  `json:"username"`
	Status             string  `json:"status"`
	IsActive           bool    `json:"isActive"`
	LastTestedAt       *string `json:"lastTestedAt,omitempty"`
	CreatedAt          string  `json:"createdAt"`
	UpdatedAt          string  `json:"updatedAt"`
}

// CreateConnection godoc
// @Summary      Create a JIRA connection
// @Description  Configures a JIRA integration for a project (manager or admin only)
// @Tags         jira
// @Accept       json
// @Produce      json
// @Param        projectId  path  string                    true  "Project ID"
// @Param        body       body  CreateJiraConnectionRequest  true  "JIRA connection details"
// @Success      201  {object}  JiraConnectionResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/projects/{projectId}/integrations/jira/connections [post]
// @Security     BearerAuth
func (h *JiraConnectionHandler) CreateConnection(c *gin.Context) {
	projectID := c.Param("projectId")

	// Check if user can manage the project
	userID := h.getUserID(c)
	if userID == "" {
		h.ErrorResponse(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Check project permissions
	permissions, err := h.projectService.GetUserPermissions(c.Request.Context(), projectsDomain.ProjectID(projectID), userID)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, "failed to get permissions")
		return
	}

	// Check if user has write permission (needed to manage connections)
	canManage := false
	for _, perm := range permissions {
		if perm.CanWrite() || perm.CanAdmin() {
			canManage = true
			break
		}
	}

	if !canManage {
		h.ErrorResponse(c, http.StatusForbidden, "forbidden")
		return
	}

	var req CreateJiraConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	connection, err := h.jiraService.CreateConnection(
		c.Request.Context(),
		projectID,
		req.Name,
		req.JiraURL,
		integrations.AuthenticationType(req.AuthenticationType),
		req.ProjectKey,
		req.Username,
		req.Credential,
	)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(c, http.StatusCreated, h.convertToResponse(connection))
}

// GetConnections godoc
// @Summary      List JIRA connections
// @Description  Returns all JIRA connections configured for a project
// @Tags         jira
// @Produce      json
// @Param        projectId  path  string  true  "Project ID"
// @Success      200  {array}   JiraConnectionResponse
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/projects/{projectId}/integrations/jira/connections [get]
// @Security     BearerAuth
func (h *JiraConnectionHandler) GetConnections(c *gin.Context) {
	projectID := c.Param("projectId")

	// Check if user can view the project
	userID := h.getUserID(c)
	if userID == "" {
		h.ErrorResponse(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	connections, err := h.jiraService.GetProjectConnections(c.Request.Context(), projectID)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	responses := make([]JiraConnectionResponse, len(connections))
	for i, conn := range connections {
		responses[i] = *h.convertToResponse(conn)
	}

	h.respondWithJSON(c, http.StatusOK, responses)
}

// GetConnection retrieves a specific JIRA connection by ID
func (h *JiraConnectionHandler) GetConnection(c *gin.Context) {
	connectionID := c.Param("connectionId")

	// Check if user can manage the connection
	userID := h.getUserID(c)
	if userID == "" {
		h.ErrorResponse(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	connection, err := h.jiraService.GetConnection(c.Request.Context(), connectionID)
	if err != nil {
		h.ErrorResponse(c, http.StatusNotFound, "connection not found")
		return
	}

	// Check project permissions
	permissions, err := h.projectService.GetUserPermissions(c.Request.Context(), projectsDomain.ProjectID(connection.ProjectID()), userID)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, "failed to get permissions")
		return
	}

	// Check if user has read permission
	canView := false
	for _, perm := range permissions {
		if perm.CanRead() {
			canView = true
			break
		}
	}

	if !canView {
		h.ErrorResponse(c, http.StatusForbidden, "forbidden")
		return
	}

	h.respondWithJSON(c, http.StatusOK, h.convertToResponse(connection))
}

// UpdateConnection godoc
// @Summary      Update a JIRA connection
// @Description  Updates name, URL, or project key for a JIRA connection (manager or admin only)
// @Tags         jira
// @Accept       json
// @Produce      json
// @Param        projectId     path  string                       true  "Project ID"
// @Param        connectionId  path  string                       true  "Connection ID"
// @Param        body          body  UpdateJiraConnectionRequest  true  "Fields to update"
// @Success      200  {object}  JiraConnectionResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/projects/{projectId}/integrations/jira/connections/{connectionId} [put]
// @Security     BearerAuth
func (h *JiraConnectionHandler) UpdateConnection(c *gin.Context) {
	connectionID := c.Param("connectionId")

	// Check if user can manage the connection
	userID := h.getUserID(c)
	if userID == "" {
		h.ErrorResponse(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	connection, err := h.jiraService.GetConnection(c.Request.Context(), connectionID)
	if err != nil {
		h.ErrorResponse(c, http.StatusNotFound, "connection not found")
		return
	}

	// Check project permissions
	permissions, err := h.projectService.GetUserPermissions(c.Request.Context(), projectsDomain.ProjectID(connection.ProjectID()), userID)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, "failed to get permissions")
		return
	}

	// Check if user has write permission
	canManage := false
	for _, perm := range permissions {
		if perm.CanWrite() || perm.CanAdmin() {
			canManage = true
			break
		}
	}

	if !canManage {
		h.ErrorResponse(c, http.StatusForbidden, "forbidden")
		return
	}

	var req UpdateJiraConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := h.jiraService.UpdateConnection(
		c.Request.Context(),
		connectionID,
		req.Name,
		req.JiraURL,
		req.ProjectKey,
	)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(c, http.StatusOK, h.convertToResponse(updated))
}

// UpdateCredentials godoc
// @Summary      Update JIRA connection credentials
// @Description  Replaces the authentication type and credential for a JIRA connection (manager or admin only)
// @Tags         jira
// @Accept       json
// @Produce      json
// @Param        projectId     path  string                        true  "Project ID"
// @Param        connectionId  path  string                        true  "Connection ID"
// @Param        body          body  UpdateJiraCredentialsRequest  true  "New credentials"
// @Success      200  {object}  JiraConnectionResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/projects/{projectId}/integrations/jira/connections/{connectionId}/credentials [put]
// @Security     BearerAuth
func (h *JiraConnectionHandler) UpdateCredentials(c *gin.Context) {
	connectionID := c.Param("connectionId")

	// Check if user can manage the connection
	userID := h.getUserID(c)
	if userID == "" {
		h.ErrorResponse(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	connection, err := h.jiraService.GetConnection(c.Request.Context(), connectionID)
	if err != nil {
		h.ErrorResponse(c, http.StatusNotFound, "connection not found")
		return
	}

	// Check project permissions
	permissions, err := h.projectService.GetUserPermissions(c.Request.Context(), projectsDomain.ProjectID(connection.ProjectID()), userID)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, "failed to get permissions")
		return
	}

	// Check if user has write permission
	canManage := false
	for _, perm := range permissions {
		if perm.CanWrite() || perm.CanAdmin() {
			canManage = true
			break
		}
	}

	if !canManage {
		h.ErrorResponse(c, http.StatusForbidden, "forbidden")
		return
	}

	var req UpdateJiraCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := h.jiraService.UpdateCredentials(
		c.Request.Context(),
		connectionID,
		integrations.AuthenticationType(req.AuthenticationType),
		req.Username,
		req.Credential,
	)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(c, http.StatusOK, h.convertToResponse(updated))
}

// TestConnection godoc
// @Summary      Test a JIRA connection
// @Description  Verifies that the stored credentials can reach JIRA (manager or admin only)
// @Tags         jira
// @Produce      json
// @Param        projectId     path  string  true  "Project ID"
// @Param        connectionId  path  string  true  "Connection ID"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/projects/{projectId}/integrations/jira/connections/{connectionId}/test [post]
// @Security     BearerAuth
func (h *JiraConnectionHandler) TestConnection(c *gin.Context) {
	connectionID := c.Param("connectionId")

	// Check if user can manage the connection
	userID := h.getUserID(c)
	if userID == "" {
		h.ErrorResponse(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	connection, err := h.jiraService.GetConnection(c.Request.Context(), connectionID)
	if err != nil {
		h.ErrorResponse(c, http.StatusNotFound, "connection not found")
		return
	}

	// Check project permissions
	permissions, err := h.projectService.GetUserPermissions(c.Request.Context(), projectsDomain.ProjectID(connection.ProjectID()), userID)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, "failed to get permissions")
		return
	}

	// Check if user has write permission
	canManage := false
	for _, perm := range permissions {
		if perm.CanWrite() || perm.CanAdmin() {
			canManage = true
			break
		}
	}

	if !canManage {
		h.ErrorResponse(c, http.StatusForbidden, "forbidden")
		return
	}

	if err := h.jiraService.TestConnection(c.Request.Context(), connectionID); err != nil {
		h.ErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(c, http.StatusOK, gin.H{"message": "Connection test successful"})
}

// DeleteConnection godoc
// @Summary      Delete a JIRA connection
// @Description  Permanently removes a JIRA connection from a project (manager or admin only)
// @Tags         jira
// @Produce      json
// @Param        projectId     path  string  true  "Project ID"
// @Param        connectionId  path  string  true  "Connection ID"
// @Success      204
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /api/v1/projects/{projectId}/integrations/jira/connections/{connectionId} [delete]
// @Security     BearerAuth
func (h *JiraConnectionHandler) DeleteConnection(c *gin.Context) {
	connectionID := c.Param("connectionId")

	// Check if user can manage the connection
	userID := h.getUserID(c)
	if userID == "" {
		h.ErrorResponse(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	connection, err := h.jiraService.GetConnection(c.Request.Context(), connectionID)
	if err != nil {
		h.ErrorResponse(c, http.StatusNotFound, "connection not found")
		return
	}

	// Check project permissions
	permissions, err := h.projectService.GetUserPermissions(c.Request.Context(), projectsDomain.ProjectID(connection.ProjectID()), userID)
	if err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, "failed to get permissions")
		return
	}

	// Check if user has write permission
	canManage := false
	for _, perm := range permissions {
		if perm.CanWrite() || perm.CanAdmin() {
			canManage = true
			break
		}
	}

	if !canManage {
		h.ErrorResponse(c, http.StatusForbidden, "forbidden")
		return
	}

	if err := h.jiraService.DeleteConnection(c.Request.Context(), connectionID); err != nil {
		h.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(c, http.StatusNoContent, nil)
}

// convertToResponse converts a domain entity to response format
func (h *JiraConnectionHandler) convertToResponse(conn *integrations.JiraConnection) *JiraConnectionResponse {
	snapshot := conn.Snapshot()

	var lastTested *string
	if snapshot.LastTestedAt != nil {
		formatted := snapshot.LastTestedAt.Format(time.RFC3339)
		lastTested = &formatted
	}

	return &JiraConnectionResponse{
		ID:                 snapshot.ID,
		ProjectID:          snapshot.ProjectID,
		Name:               snapshot.Name,
		JiraURL:            snapshot.JiraURL,
		AuthenticationType: string(snapshot.AuthenticationType),
		ProjectKey:         snapshot.ProjectKey,
		Username:           snapshot.Username,
		Status:             string(snapshot.Status),
		IsActive:           snapshot.IsActive,
		LastTestedAt:       lastTested,
		CreatedAt:          snapshot.CreatedAt.Format(time.RFC3339),
		UpdatedAt:          snapshot.UpdatedAt.Format(time.RFC3339),
	}
}
