package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/yourusername/vane/config"
	"github.com/yourusername/vane/module/ddns"
	"github.com/yourusername/vane/module/portforward"
	tlsmod "github.com/yourusername/vane/module/tls"
	"github.com/yourusername/vane/module/webservice"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Handler struct {
	cfg  *config.Config
	pf   *portforward.Manager
	ddns *ddns.Manager
	ws   *webservice.Manager
	tls  *tlsmod.Manager
}

func NewHandler(cfg *config.Config, pf *portforward.Manager, d *ddns.Manager,
	ws *webservice.Manager, t *tlsmod.Manager) *Handler {
	return &Handler{cfg: cfg, pf: pf, ddns: d, ws: ws, tls: t}
}

// Register wires all routes.
func (h *Handler) Register(r *gin.Engine) {
	api := r.Group("/api")

	// Public
	api.POST("/login", h.rateLimitMiddleware(), h.login)
	api.POST("/logout", h.logout)

	auth := api.Group("/")
	auth.Use(h.authMiddleware())

	// Dashboard + WS
	auth.GET("/dashboard", h.getDashboard)
	auth.GET("/ws/stats", h.wsStats)

	// Settings
	auth.GET("/settings", h.getSettings)
	auth.PUT("/settings", h.updateSettings)
	auth.GET("/settings/backup", h.backupConfig)
	auth.POST("/settings/restore", h.restoreConfig)

	// Port Forward
	auth.GET("/portforward", h.listPortForwards)
	auth.POST("/portforward", h.createPortForward)
	auth.PUT("/portforward/:id", h.updatePortForward)
	auth.DELETE("/portforward/:id", h.deletePortForward)
	auth.POST("/portforward/:id/toggle", h.togglePortForward)
	auth.GET("/portforward/:id/stats", h.getPortForwardStats)

	// DDNS
	auth.GET("/ddns", h.listDDNS)
	auth.GET("/ddns/interfaces", h.listInterfaces)
	auth.GET("/ddns/iface-ips", h.listIfaceIPs)
	auth.POST("/ddns", h.createDDNS)
	auth.PUT("/ddns/:id", h.updateDDNS)
	auth.DELETE("/ddns/:id", h.deleteDDNS)
	auth.POST("/ddns/:id/toggle", h.toggleDDNS)
	auth.POST("/ddns/:id/refresh", h.refreshDDNS)

	// Web Service
	auth.GET("/webservice", h.listWebServices)
	auth.POST("/webservice", h.createWebService)
	auth.PUT("/webservice/:id", h.updateWebService)
	auth.DELETE("/webservice/:id", h.deleteWebService)
	auth.POST("/webservice/:id/toggle", h.toggleWebService)
	// Sub-routes
	auth.GET("/webservice/:id/routes", h.listRoutes)
	auth.POST("/webservice/:id/routes", h.createRoute)
	auth.PUT("/webservice/:id/routes/:rid", h.updateRoute)
	auth.DELETE("/webservice/:id/routes/:rid", h.deleteRoute)
	auth.POST("/webservice/:id/routes/:rid/toggle", h.toggleRoute)
	// Access logs
	auth.GET("/webservice/:id/logs", h.getAccessLogs)
	auth.GET("/webservice/logs", h.getAllAccessLogs)

	// Port availability check
	auth.GET("/check-port", h.checkPort)

	// TLS
	auth.GET("/tls", h.listCerts)
	auth.POST("/tls", h.createCert)
	auth.PUT("/tls/:id", h.updateCert)
	auth.DELETE("/tls/:id", h.deleteCert)
	auth.POST("/tls/:id/issue", h.issueCert)
	auth.POST("/tls/upload", h.uploadCert)
	auth.GET("/tls/:id/download", h.downloadCert)
	auth.GET("/tls/:id/pem", h.getCertPEM)
}

// ─── Safe Entry Middleware ────────────────────────────────────────────────────

func SafeEntryMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg.RLock()
		entry := cfg.Admin.SafeEntry
		cfg.RUnlock()

		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/") {
			c.Next()
			return
		}
		if entry == "" {
			c.Next()
			return
		}
		prefix := "/" + strings.Trim(entry, "/")
		if strings.HasPrefix(path, prefix) {
			c.Next()
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
	}
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

type loginAttempt struct {
	count    int
	windowAt time.Time
}

var (
	loginMu       sync.Mutex
	loginAttempts = make(map[string]*loginAttempt)
)

const (
	maxLoginAttempts = 10
	loginWindow      = 10 * time.Minute
)

func (h *Handler) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		loginMu.Lock()
		a, ok := loginAttempts[ip]
		if !ok || time.Since(a.windowAt) > loginWindow {
			loginAttempts[ip] = &loginAttempt{count: 0, windowAt: time.Now()}
			a = loginAttempts[ip]
		}
		a.count++
		count := a.count
		loginMu.Unlock()

		if count > maxLoginAttempts {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "登录尝试次数过多，请10分钟后重试"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

func (h *Handler) login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	h.cfg.RLock()
	ok := h.cfg.Admin.Username == req.Username && h.cfg.Admin.CheckPassword(req.Password)
	h.cfg.RUnlock()
	if !ok {
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}
	// Reset rate-limit counter on success
	loginMu.Lock()
	delete(loginAttempts, c.ClientIP())
	loginMu.Unlock()

	token := generateToken()
	sessions.set(token, time.Now().Add(24*time.Hour))
	c.JSON(200, gin.H{"token": token})
}

func (h *Handler) logout(c *gin.Context) {
	sessions.delete(c.GetHeader("Authorization"))
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		// WebSocket clients cannot set custom headers; allow token via query param
		if token == "" {
			token = c.Query("token")
		}
		if token == "" {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		exp, ok := sessions.get(token)
		if !ok || time.Now().After(exp) {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		// Slide expiry
		sessions.set(token, time.Now().Add(24*time.Hour))
		c.Next()
	}
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

func (h *Handler) getDashboard(c *gin.Context) {
	h.cfg.RLock()
	certsSoon := 0
	for _, cert := range h.cfg.TLSCerts {
		d := cert.DaysUntilExpiry()
		if d >= 0 && d <= 30 {
			certsSoon++
		}
	}
	dash := gin.H{
		"port_forwards":       len(h.cfg.PortForwards),
		"ddns":                len(h.cfg.DDNS),
		"web_services":        len(h.cfg.WebServices),
		"tls_certs":           len(h.cfg.TLSCerts),
		"certs_expiring_soon": certsSoon,
	}
	h.cfg.RUnlock()
	c.JSON(200, dash)
}

func (h *Handler) wsStats(c *gin.Context) {
	// WebSocket auth: token must be in Authorization header (set by WS client)
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.cfg.RLock()
		rules := make([]config.PortForwardRule, len(h.cfg.PortForwards))
		copy(rules, h.cfg.PortForwards)
		h.cfg.RUnlock()
		stats := make(map[string]interface{})
		for _, r := range rules {
			if s := h.pf.GetStats(r.ID); s != nil {
				stats[r.ID] = s.Snapshot()
			}
		}
		if err := conn.WriteJSON(gin.H{"type": "stats", "data": stats, "time": time.Now()}); err != nil {
			return
		}
	}
}

// ─── Port availability check ──────────────────────────────────────────────────

func (h *Handler) checkPort(c *gin.Context) {
	portStr := c.Query("port")
	var port int
	if _, err := parsePort(portStr, &port); err != nil {
		c.JSON(400, gin.H{"error": "invalid port"})
		return
	}
	available := config.IsPortAvailable(port)
	c.JSON(200, gin.H{"port": port, "available": available})
}

func parsePort(s string, out *int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port: %s", s)
	}
	*out = n
	return n, nil
}

// ─── Settings ─────────────────────────────────────────────────────────────────

func (h *Handler) getSettings(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, gin.H{
		"username":   h.cfg.Admin.Username,
		"port":       h.cfg.Admin.Port,
		"safe_entry": h.cfg.Admin.SafeEntry,
	})
}

func (h *Handler) updateSettings(c *gin.Context) {
	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"new_password"`
		Port        int    `json:"port"`
		SafeEntry   string `json:"safe_entry"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.cfg.Lock()
	if req.Username != "" {
		h.cfg.Admin.Username = req.Username
	}
	if req.NewPassword != "" {
		if err := h.cfg.Admin.SetPassword(req.NewPassword); err != nil {
			h.cfg.Unlock()
			c.JSON(500, gin.H{"error": "密码设置失败"})
			return
		}
	}
	if req.Port > 0 {
		h.cfg.Admin.Port = req.Port
	}
	h.cfg.Admin.SafeEntry = strings.Trim(req.SafeEntry, "/")
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存配置失败: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) backupConfig(c *gin.Context) {
	name, err := h.cfg.SaveBackup()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	data, err := h.cfg.Export()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	c.Data(200, "application/octet-stream", data)
}

func (h *Handler) restoreConfig(c *gin.Context) {
	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "read body failed"})
		return
	}
	if err := h.cfg.Import(data); err != nil {
		c.JSON(400, gin.H{"error": "invalid config: " + err.Error()})
		return
	}
	h.pf.StartAll()
	h.ddns.StartAll()
	h.ws.StartAll()
	c.JSON(200, gin.H{"ok": true, "message": "配置已恢复，服务已重启"})
}

// ─── Port Forward ─────────────────────────────────────────────────────────────

func (h *Handler) listPortForwards(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, h.cfg.PortForwards)
}

func (h *Handler) createPortForward(c *gin.Context) {
	var rule config.PortForwardRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if rule.ListenPort < 1 || rule.ListenPort > 65535 {
		c.JSON(400, gin.H{"error": "无效端口"})
		return
	}
	if rule.Enabled && !config.IsPortAvailable(rule.ListenPort) {
		c.JSON(409, gin.H{"error": "端口已被占用", "port": rule.ListenPort})
		return
	}
	rule.ID = config.NewID()
	rule.CreatedAt = config.Now()
	h.cfg.Lock()
	h.cfg.PortForwards = append(h.cfg.PortForwards, rule)
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	if rule.Enabled {
		_ = h.pf.Start(rule.ID)
	}
	c.JSON(201, rule)
}

func (h *Handler) updatePortForward(c *gin.Context) {
	id := c.Param("id")
	var req config.PortForwardRule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// Stop the old listener before port check
	h.pf.Stop(id)
	if req.Enabled && !config.IsPortAvailable(req.ListenPort) {
		c.JSON(409, gin.H{"error": "端口已被占用", "port": req.ListenPort})
		return
	}
	h.cfg.Lock()
	for i := range h.cfg.PortForwards {
		if h.cfg.PortForwards[i].ID == id {
			req.ID = id
			req.CreatedAt = h.cfg.PortForwards[i].CreatedAt
			h.cfg.PortForwards[i] = req
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	if req.Enabled {
		_ = h.pf.Start(id)
	}
	c.JSON(200, req)
}

func (h *Handler) deletePortForward(c *gin.Context) {
	id := c.Param("id")
	h.pf.Stop(id)
	h.cfg.Lock()
	for i, r := range h.cfg.PortForwards {
		if r.ID == id {
			h.cfg.PortForwards = append(h.cfg.PortForwards[:i], h.cfg.PortForwards[i+1:]...)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) togglePortForward(c *gin.Context) {
	id := c.Param("id")
	h.cfg.Lock()
	var enabled bool
	var port int
	for i := range h.cfg.PortForwards {
		if h.cfg.PortForwards[i].ID == id {
			h.cfg.PortForwards[i].Enabled = !h.cfg.PortForwards[i].Enabled
			enabled = h.cfg.PortForwards[i].Enabled
			port = h.cfg.PortForwards[i].ListenPort
			break
		}
	}
	h.cfg.Unlock()
	if enabled {
		h.pf.Stop(id) // ensure old is gone
		if !config.IsPortAvailable(port) {
			// Roll back
			h.cfg.Lock()
			for i := range h.cfg.PortForwards {
				if h.cfg.PortForwards[i].ID == id {
					h.cfg.PortForwards[i].Enabled = false
					break
				}
			}
			h.cfg.Unlock()
			_ = h.cfg.Save()
			c.JSON(409, gin.H{"error": "端口已被占用", "port": port})
			return
		}
		_ = h.pf.Start(id)
	} else {
		h.pf.Stop(id)
	}
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

func (h *Handler) getPortForwardStats(c *gin.Context) {
	c.JSON(200, gin.H{"history": h.pf.GetHistory(c.Param("id"))})
}

// ─── DDNS ─────────────────────────────────────────────────────────────────────

func (h *Handler) listDDNS(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, h.cfg.DDNS)
}

func (h *Handler) createDDNS(c *gin.Context) {
	var rule config.DDNSRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	rule.ID = config.NewID()
	rule.CreatedAt = config.Now()
	h.cfg.Lock()
	h.cfg.DDNS = append(h.cfg.DDNS, rule)
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	if rule.Enabled {
		h.ddns.Start(rule.ID)
	}
	c.JSON(201, rule)
}

func (h *Handler) updateDDNS(c *gin.Context) {
	id := c.Param("id")
	var req config.DDNSRule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.cfg.Lock()
	for i := range h.cfg.DDNS {
		if h.cfg.DDNS[i].ID == id {
			req.ID = id
			req.CreatedAt = h.cfg.DDNS[i].CreatedAt
			h.cfg.DDNS[i] = req
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	h.ddns.Stop(id)
	if req.Enabled {
		h.ddns.Start(id)
	}
	c.JSON(200, req)
}

func (h *Handler) deleteDDNS(c *gin.Context) {
	id := c.Param("id")
	h.ddns.Stop(id)
	h.cfg.Lock()
	for i, r := range h.cfg.DDNS {
		if r.ID == id {
			h.cfg.DDNS = append(h.cfg.DDNS[:i], h.cfg.DDNS[i+1:]...)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) toggleDDNS(c *gin.Context) {
	id := c.Param("id")
	h.cfg.Lock()
	var enabled bool
	for i := range h.cfg.DDNS {
		if h.cfg.DDNS[i].ID == id {
			h.cfg.DDNS[i].Enabled = !h.cfg.DDNS[i].Enabled
			enabled = h.cfg.DDNS[i].Enabled
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	if enabled {
		h.ddns.Start(id)
	} else {
		h.ddns.Stop(id)
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

func (h *Handler) refreshDDNS(c *gin.Context) {
	id := c.Param("id")
	h.ddns.Stop(id)
	h.ddns.Start(id)
	c.JSON(200, gin.H{"ok": true})
}

// ─── Web Service ──────────────────────────────────────────────────────────────

func (h *Handler) listWebServices(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, h.cfg.WebServices)
}

func (h *Handler) createWebService(c *gin.Context) {
	var svc config.WebService
	if err := c.ShouldBindJSON(&svc); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if svc.ListenPort < 1 || svc.ListenPort > 65535 {
		c.JSON(400, gin.H{"error": "无效端口"})
		return
	}
	// Check port availability before binding
	if svc.Enabled && !config.IsPortAvailable(svc.ListenPort) {
		c.JSON(409, gin.H{
			"error": "端口已被占用，无法启动服务",
			"port":  svc.ListenPort,
		})
		return
	}
	svc.ID = config.NewID()
	svc.CreatedAt = config.Now()
	if svc.Routes == nil {
		svc.Routes = []config.WebRoute{}
	}
	h.cfg.Lock()
	h.cfg.WebServices = append(h.cfg.WebServices, svc)
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	if svc.Enabled {
		if err := h.ws.Start(svc.ID); err != nil {
			c.JSON(500, gin.H{"error": "服务启动失败: " + err.Error()})
			return
		}
	}
	c.JSON(201, svc)
}

func (h *Handler) updateWebService(c *gin.Context) {
	id := c.Param("id")
	var req config.WebService
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// Stop first so port is freed before we check
	h.ws.Stop(id)
	if req.Enabled && !config.IsPortAvailable(req.ListenPort) {
		c.JSON(409, gin.H{"error": "端口已被占用", "port": req.ListenPort})
		return
	}
	h.cfg.Lock()
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == id {
			req.ID = id
			req.CreatedAt = h.cfg.WebServices[i].CreatedAt
			if req.Routes == nil {
				req.Routes = h.cfg.WebServices[i].Routes
			}
			h.cfg.WebServices[i] = req
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	if req.Enabled {
		if err := h.ws.Start(id); err != nil {
			c.JSON(500, gin.H{"error": "服务启动失败: " + err.Error()})
			return
		}
	}
	c.JSON(200, req)
}

func (h *Handler) deleteWebService(c *gin.Context) {
	id := c.Param("id")
	h.ws.Stop(id)
	h.cfg.Lock()
	for i, s := range h.cfg.WebServices {
		if s.ID == id {
			h.cfg.WebServices = append(h.cfg.WebServices[:i], h.cfg.WebServices[i+1:]...)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) toggleWebService(c *gin.Context) {
	id := c.Param("id")
	h.cfg.Lock()
	var enabled bool
	var port int
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == id {
			h.cfg.WebServices[i].Enabled = !h.cfg.WebServices[i].Enabled
			enabled = h.cfg.WebServices[i].Enabled
			port = h.cfg.WebServices[i].ListenPort
			break
		}
	}
	h.cfg.Unlock()
	if enabled {
		h.ws.Stop(id)
		if !config.IsPortAvailable(port) {
			h.cfg.Lock()
			for i := range h.cfg.WebServices {
				if h.cfg.WebServices[i].ID == id {
					h.cfg.WebServices[i].Enabled = false
					break
				}
			}
			h.cfg.Unlock()
			_ = h.cfg.Save()
			c.JSON(409, gin.H{"error": "端口已被占用", "port": port})
			return
		}
		if err := h.ws.Start(id); err != nil {
			c.JSON(500, gin.H{"error": "服务启动失败: " + err.Error()})
			return
		}
	} else {
		h.ws.Stop(id)
	}
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

// ─── Web Routes ───────────────────────────────────────────────────────────────

func (h *Handler) listRoutes(c *gin.Context) {
	id := c.Param("id")
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	for _, svc := range h.cfg.WebServices {
		if svc.ID == id {
			c.JSON(200, svc.Routes)
			return
		}
	}
	c.JSON(404, gin.H{"error": "service not found"})
}

func (h *Handler) createRoute(c *gin.Context) {
	id := c.Param("id")
	var route config.WebRoute
	if err := c.ShouldBindJSON(&route); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	route.ID = config.NewID()
	route.CreatedAt = config.Now()
	h.cfg.Lock()
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == id {
			h.cfg.WebServices[i].Routes = append(h.cfg.WebServices[i].Routes, route)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	h.ws.Stop(id)
	_ = h.ws.Start(id)
	c.JSON(201, route)
}

func (h *Handler) updateRoute(c *gin.Context) {
	svcID, rid := c.Param("id"), c.Param("rid")
	var req config.WebRoute
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.cfg.Lock()
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == svcID {
			for j := range h.cfg.WebServices[i].Routes {
				if h.cfg.WebServices[i].Routes[j].ID == rid {
					req.ID = rid
					req.CreatedAt = h.cfg.WebServices[i].Routes[j].CreatedAt
					h.cfg.WebServices[i].Routes[j] = req
					break
				}
			}
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	h.ws.Stop(svcID)
	_ = h.ws.Start(svcID)
	c.JSON(200, req)
}

func (h *Handler) deleteRoute(c *gin.Context) {
	svcID, rid := c.Param("id"), c.Param("rid")
	h.cfg.Lock()
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == svcID {
			routes := h.cfg.WebServices[i].Routes
			for j, r := range routes {
				if r.ID == rid {
					h.cfg.WebServices[i].Routes = append(routes[:j], routes[j+1:]...)
					break
				}
			}
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	h.ws.Stop(svcID)
	_ = h.ws.Start(svcID)
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) toggleRoute(c *gin.Context) {
	svcID, rid := c.Param("id"), c.Param("rid")
	h.cfg.Lock()
	var enabled bool
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == svcID {
			for j := range h.cfg.WebServices[i].Routes {
				if h.cfg.WebServices[i].Routes[j].ID == rid {
					h.cfg.WebServices[i].Routes[j].Enabled = !h.cfg.WebServices[i].Routes[j].Enabled
					enabled = h.cfg.WebServices[i].Routes[j].Enabled
					break
				}
			}
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	h.ws.Stop(svcID)
	_ = h.ws.Start(svcID)
	c.JSON(200, gin.H{"enabled": enabled})
}

// ─── Access Logs ──────────────────────────────────────────────────────────────

func (h *Handler) getAccessLogs(c *gin.Context) {
	logs := webservice.GetLogs().List(c.Param("id"), 200)
	c.JSON(200, logs)
}

func (h *Handler) getAllAccessLogs(c *gin.Context) {
	logs := webservice.GetLogs().List("", 500)
	c.JSON(200, logs)
}

// ─── TLS ──────────────────────────────────────────────────────────────────────

func (h *Handler) listCerts(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	type certView struct {
		ID        string `json:"id"`
		Domain    string `json:"domain"`
		Source    string `json:"source"`
		Provider  string `json:"provider"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
		AutoRenew bool   `json:"auto_renew"`
		Status    string `json:"status"`
		DaysLeft  int    `json:"days_left"`
		CreatedAt string `json:"created_at"`
	}
	views := make([]certView, 0, len(h.cfg.TLSCerts))
	for _, cert := range h.cfg.TLSCerts {
		views = append(views, certView{
			ID: cert.ID, Domain: cert.Domain, Source: cert.Source,
			Provider: cert.Provider, IssuedAt: cert.IssuedAt,
			ExpiresAt: cert.ExpiresAt, AutoRenew: cert.AutoRenew,
			Status: cert.Status, DaysLeft: cert.DaysUntilExpiry(),
			CreatedAt: cert.CreatedAt,
		})
	}
	c.JSON(200, views)
}

func (h *Handler) createCert(c *gin.Context) {
	var cert config.TLSCert
	if err := c.ShouldBindJSON(&cert); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	cert.ID = config.NewID()
	cert.CreatedAt = config.Now()
	cert.Status = "pending"
	h.cfg.Lock()
	h.cfg.TLSCerts = append(h.cfg.TLSCerts, cert)
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(201, cert)
}

func (h *Handler) updateCert(c *gin.Context) {
	id := c.Param("id")
	var req config.TLSCert
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.cfg.Lock()
	for i := range h.cfg.TLSCerts {
		if h.cfg.TLSCerts[i].ID == id {
			req.ID = id
			req.CreatedAt = h.cfg.TLSCerts[i].CreatedAt
			if req.CertPEM == "" {
				req.CertPEM = h.cfg.TLSCerts[i].CertPEM
				req.KeyPEM = h.cfg.TLSCerts[i].KeyPEM
			}
			h.cfg.TLSCerts[i] = req
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) deleteCert(c *gin.Context) {
	id := c.Param("id")
	h.cfg.Lock()
	for i, cert := range h.cfg.TLSCerts {
		if cert.ID == id {
			h.cfg.TLSCerts = append(h.cfg.TLSCerts[:i], h.cfg.TLSCerts[i+1:]...)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) issueCert(c *gin.Context) {
	id := c.Param("id")
	go func() {
		if err := h.tls.IssueCert(id); err != nil {
			h.cfg.Lock()
			for i := range h.cfg.TLSCerts {
				if h.cfg.TLSCerts[i].ID == id {
					h.cfg.TLSCerts[i].Status = "error"
					break
				}
			}
			h.cfg.Unlock()
			_ = h.cfg.Save()
		}
	}()
	h.cfg.Lock()
	for i := range h.cfg.TLSCerts {
		if h.cfg.TLSCerts[i].ID == id {
			h.cfg.TLSCerts[i].Status = "pending"
			break
		}
	}
	h.cfg.Unlock()
	c.JSON(202, gin.H{"ok": true})
}

func (h *Handler) uploadCert(c *gin.Context) {
	var req struct {
		Domain    string `json:"domain"`
		CertPEM   string `json:"cert_pem"`
		KeyPEM    string `json:"key_pem"`
		AutoRenew bool   `json:"auto_renew"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	cert := config.TLSCert{
		ID:        config.NewID(),
		Domain:    req.Domain,
		Source:    "manual",
		CertPEM:   req.CertPEM,
		KeyPEM:    req.KeyPEM,
		IssuedAt:  config.Now(),
		AutoRenew: req.AutoRenew,
		Status:    "active",
		CreatedAt: config.Now(),
	}
	h.cfg.Lock()
	h.cfg.TLSCerts = append(h.cfg.TLSCerts, cert)
	h.cfg.Unlock()
	if err := h.cfg.Save(); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(201, cert)
}

// ─── TLS download ─────────────────────────────────────────────────────────────

// downloadCert returns a zip containing cert.pem + key.pem
func (h *Handler) downloadCert(c *gin.Context) {
	id := c.Param("id")
	h.cfg.RLock()
	var found *config.TLSCert
	for i := range h.cfg.TLSCerts {
		if h.cfg.TLSCerts[i].ID == id {
			cert := h.cfg.TLSCerts[i]
			found = &cert
			break
		}
	}
	h.cfg.RUnlock()
	if found == nil {
		c.JSON(404, gin.H{"error": "cert not found"})
		return
	}
	if found.CertPEM == "" || found.KeyPEM == "" {
		c.JSON(400, gin.H{"error": "证书尚未签发，无法下载"})
		return
	}
	// Return as multipart JSON with both files
	domain := found.Domain
	c.Header("Content-Disposition", `attachment; filename="`+domain+`-cert.pem"`)
	c.Data(200, "application/x-pem-file", []byte(found.CertPEM))
}

// getCertPEM returns cert + key PEM as JSON (for copy-paste)
func (h *Handler) getCertPEM(c *gin.Context) {
	id := c.Param("id")
	h.cfg.RLock()
	var found *config.TLSCert
	for i := range h.cfg.TLSCerts {
		if h.cfg.TLSCerts[i].ID == id {
			cert := h.cfg.TLSCerts[i]
			found = &cert
			break
		}
	}
	h.cfg.RUnlock()
	if found == nil {
		c.JSON(404, gin.H{"error": "cert not found"})
		return
	}
	c.JSON(200, gin.H{
		"cert_pem": found.CertPEM,
		"key_pem":  found.KeyPEM,
		"domain":   found.Domain,
	})
}

func (h *Handler) listInterfaces(c *gin.Context) {
	c.JSON(200, ddns.GetInterfaces())
}

// GET /api/ddns/iface-ips?iface=eth0&version=ipv6
// Returns list of suitable IPs on the given interface — used to preview
// which IPv6 addresses are available so user can pick by index.
func (h *Handler) listIfaceIPs(c *gin.Context) {
	iface := c.Query("iface")
	version := c.DefaultQuery("version", "ipv4")
	if iface == "" {
		c.JSON(400, gin.H{"error": "iface required"})
		return
	}
	ips, err := ddns.ListInterfaceIPs(iface, version)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ips)
}
