package webservice

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/vane/config"
)

// ─── Access log store (in-memory ring buffer, 2000 entries) ──────────────────

const maxLogs = 2000

type LogStore struct {
	mu   sync.Mutex
	logs []config.WebAccessLog
}

var globalLogs = &LogStore{}

func (s *LogStore) Add(l config.WebAccessLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, l)
	if len(s.logs) > maxLogs {
		s.logs = s.logs[len(s.logs)-maxLogs:]
	}
}

func (s *LogStore) List(serviceID string, limit int) []config.WebAccessLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]config.WebAccessLog, 0, limit)
	for i := len(s.logs) - 1; i >= 0 && len(result) < limit; i-- {
		if serviceID == "" || s.logs[i].ServiceID == serviceID {
			result = append(result, s.logs[i])
		}
	}
	return result
}

func GetLogs() *LogStore { return globalLogs }

// ─── responseRecorder ────────────────────────────────────────────────────────

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ─── Manager ─────────────────────────────────────────────────────────────────

type Manager struct {
	cfg     *config.Config
	mu      sync.Mutex
	servers map[string]*managedServer
}

type managedServer struct {
	httpSrv  *http.Server
	httpsSrv *http.Server
}

func (ms *managedServer) close() {
	if ms.httpSrv != nil {
		_ = ms.httpSrv.Close()
	}
	if ms.httpsSrv != nil {
		_ = ms.httpsSrv.Close()
	}
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg, servers: make(map[string]*managedServer)}
}

func (m *Manager) StartAll() {
	m.cfg.RLock()
	svcs := make([]config.WebService, len(m.cfg.WebServices))
	copy(svcs, m.cfg.WebServices)
	m.cfg.RUnlock()

	for _, svc := range svcs {
		if svc.Enabled {
			if err := m.Start(svc.ID); err != nil {
				log.Printf("[webservice] start %s error: %v", svc.ID, err)
			}
		}
	}
}

func (m *Manager) Start(id string) error {
	m.cfg.RLock()
	var svc *config.WebService
	for i := range m.cfg.WebServices {
		if m.cfg.WebServices[i].ID == id {
			s := m.cfg.WebServices[i]
			svc = &s
			break
		}
	}
	m.cfg.RUnlock()
	if svc == nil {
		return fmt.Errorf("service %s not found", id)
	}

	m.mu.Lock()
	if old, ok := m.servers[id]; ok {
		old.close()
		delete(m.servers, id)
	}
	m.mu.Unlock()

	ms := &managedServer{}
	router := m.buildRouter(svc)

	if svc.EnableHTTPS {
		cert, key := m.getCertPEM(svc.TLSCertID)
		if cert == "" || key == "" {
			// No cert available yet - fall through to plain HTTP
			log.Printf("[webservice] HTTPS requested but no cert for service %s, starting HTTP only", svc.Name)
			goto plainHTTP
		}
		tlsCert, err := tls.X509KeyPair([]byte(cert), []byte(key))
		if err != nil {
			return fmt.Errorf("TLS load error: %w", err)
		}

		// HTTPS on configured port
		httpsAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
		ms.httpsSrv = &http.Server{
			Addr:    httpsAddr,
			Handler: router,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				MinVersion:   tls.VersionTLS12,
			},
		}
		go func() {
			log.Printf("[webservice] HTTPS :%d (service %s)", svc.ListenPort, svc.Name)
			if err := ms.httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("[webservice] HTTPS error: %v", err)
			}
		}()

		// HTTP redirect on port+1 (only if port != 80/443 convention)
		// For standard setup: if HTTPS on 443, HTTP redirect on 80
		httpPort := svc.ListenPort + 1
		if svc.ListenPort == 443 {
			httpPort = 80
		}
		httpAddr := fmt.Sprintf("0.0.0.0:%d", httpPort)
		ms.httpSrv = &http.Server{
			Addr: httpAddr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.RequestURI
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}),
		}
		go func() {
			log.Printf("[webservice] HTTP→HTTPS redirect :%d (service %s)", httpPort, svc.Name)
			if err := ms.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[webservice] HTTP redirect error: %v", err)
			}
		}()

		m.mu.Lock()
		m.servers[id] = ms
		m.mu.Unlock()
		return nil
	}

plainHTTP:
	// Plain HTTP
	httpAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
	ms.httpSrv = &http.Server{Addr: httpAddr, Handler: router}
	go func() {
		log.Printf("[webservice] HTTP :%d (service %s)", svc.ListenPort, svc.Name)
		if err := ms.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[webservice] HTTP error: %v", err)
		}
	}()

	m.mu.Lock()
	m.servers[id] = ms
	m.mu.Unlock()
	return nil
}

func (m *Manager) Stop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ms, ok := m.servers[id]; ok {
		ms.close()
		delete(m.servers, id)
	}
}

// buildRouter creates an http.Handler that dispatches by Host header.
func (m *Manager) buildRouter(svc *config.WebService) http.Handler {
	type entry struct {
		route config.WebRoute
		proxy *httputil.ReverseProxy
	}

	entries := make([]entry, 0, len(svc.Routes))
	for _, route := range svc.Routes {
		if !route.Enabled {
			continue
		}
		target, err := url.Parse(route.BackendURL)
		if err != nil {
			log.Printf("[webservice] invalid backend %q: %v", route.BackendURL, err)
			continue
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		orig := proxy.Director
		proxy.Director = func(req *http.Request) {
			orig(req)
			req.Host = target.Host
		}
		entries = append(entries, entry{route: route, proxy: proxy})
	}

	svcID := svc.ID

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		start := time.Now()
		rr := &responseRecorder{ResponseWriter: w, status: 200}

		for _, e := range entries {
			routeDomain := strings.TrimPrefix(e.route.Domain, "www.")
			reqDomain := strings.TrimPrefix(host, "www.")
			if strings.EqualFold(routeDomain, reqDomain) {
				e.proxy.ServeHTTP(rr, r)
				logAccess(svcID, e.route.ID, e.route.Domain, r, rr.status, time.Since(start))
				return
			}
		}

		http.Error(w, "No matching route for host: "+host, http.StatusBadGateway)
		logAccess(svcID, "", host, r, http.StatusBadGateway, time.Since(start))
	})
}

// logAccess records one request. Client IP is taken from the TCP connection
// only; X-Forwarded-For and X-Real-IP are NOT trusted to prevent spoofing.
func logAccess(svcID, routeID, domain string, r *http.Request, status int, dur time.Duration) {
	// Use only the verified remote address (TCP peer), never HTTP headers.
	clientIP := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = ip
	}

	globalLogs.Add(config.WebAccessLog{
		ID:         config.NewID(),
		ServiceID:  svcID,
		RouteID:    routeID,
		Domain:     domain,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: status,
		DurationMs: dur.Milliseconds(),
		ClientIP:   clientIP,
		UserAgent:  r.UserAgent(),
		Referer:    r.Referer(),
		Time:       config.Now(),
	})
}

func (m *Manager) getCertPEM(certID string) (cert, key string) {
	m.cfg.RLock()
	defer m.cfg.RUnlock()
	for _, c := range m.cfg.TLSCerts {
		if c.ID == certID {
			return c.CertPEM, c.KeyPEM
		}
	}
	return "", ""
}
