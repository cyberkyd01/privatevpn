//go:build !android

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/skip2/go-qrcode"

	"github.com/cyberkyd01/privatevpn/core/api"
)

const prefix = "/api/v1"

// route maps one HTTP endpoint of §14.1 to a core method. When param is set,
// the {id} path value is merged into the args JSON under that name
// (overriding any body field of the same name).
type route struct {
	method string
	path   string // below /api/v1
	core   string
	param  string
}

// routeTable is §14.1 minus the web-only endpoints (/session, /events,
// /keyring/{id}/qr.png), which are registered separately.
var routeTable = []route{
	{"GET", "/status", api.StatusGet, ""},
	{"GET", "/keyring", api.KeyringList, ""},
	{"POST", "/keyring", api.KeyringAdd, ""},
	{"POST", "/keyring/create", api.KeyringCreate, ""},
	{"PATCH", "/keyring/{id}", api.KeyringRename, "id"},
	{"DELETE", "/keyring/{id}", api.KeyringRemove, "id"},
	{"POST", "/keyring/{id}/reveal", api.KeyringReveal, "id"},
	{"POST", "/gateway/network", api.GatewaySetNetwork, ""},
	{"POST", "/gateway/reset-key", api.GatewayResetKey, ""},
	{"POST", "/gateway/enable", api.GatewayEnable, ""},
	{"POST", "/gateway/disable", api.GatewayDisable, ""},
	{"GET", "/gateways", api.GatewaysList, ""},
	{"POST", "/gateways/{id}/unlock", api.GatewaysUnlock, "gateway_id"},
	{"POST", "/gateways/manual", api.GatewaysManualAdd, ""},
	{"DELETE", "/gateways/manual/{id}", api.GatewaysManualRm, "id"},
	{"GET", "/gateways/{id}/info", api.GatewaysInfo, "gateway_id"},
	{"POST", "/client/connect", api.ClientConnect, ""},
	{"POST", "/client/disconnect", api.ClientDisconnect, ""},
	{"POST", "/client/selftest", api.ClientSelftest, ""},
	{"GET", "/settings", api.SettingsGet, ""},
	{"PUT", "/settings", api.SettingsSet, ""},
	{"POST", "/firewall/add", api.FirewallAdd, ""},
	{"GET", "/log", api.LogGet, ""},
	{"POST", "/quit", api.AppQuit, ""},
}

// reqInfo is attached to authenticated API requests by serveAPI.
type reqInfo struct {
	sess sessionRef
	body []byte // nil when empty
}

type ctxKey struct{}

func info(r *http.Request) *reqInfo {
	ri, _ := r.Context().Value(ctxKey{}).(*reqInfo)
	if ri == nil {
		return &reqInfo{}
	}
	return ri
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	for _, rt := range routeTable {
		mux.HandleFunc(rt.method+" "+prefix+rt.path, s.callHandler(rt))
	}
	mux.HandleFunc("GET "+prefix+"/keyring/{id}/qr.png", s.handleQR)
	mux.HandleFunc("GET "+prefix+"/events", s.handleEvents)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, api.CodeNotFound, "no such endpoint")
	})
	return mux
}

// serveAPI authenticates /api/* and dispatches to the mux.
func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	if !fetchSiteOK(r) {
		writeErr(w, http.StatusForbidden, "forbidden", "cross-site request refused")
		return
	}
	if r.URL.Path == prefix+"/session" {
		s.handleSession(w, r)
		return
	}
	now := s.now()
	sess, ok := s.auth.lookup(r, now)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "not signed in — open PrivateVPN from the tray icon")
		return
	}
	var body []byte
	if !isSafeMethod(r.Method) {
		if !s.originOK(r) {
			writeErr(w, http.StatusForbidden, "forbidden", "bad origin")
			return
		}
		if !csrfOK(r, sess.csrf) {
			writeErr(w, http.StatusForbidden, "forbidden", "missing or wrong CSRF token")
			return
		}
		b, ok := readBody(w, r)
		if !ok {
			return
		}
		body = b
	}
	ctx := context.WithValue(r.Context(), ctxKey{}, &reqInfo{sess: sess, body: body})
	s.mux.ServeHTTP(w, r.WithContext(ctx))
}

// buildArgs validates the body as a JSON object and merges path params.
func buildArgs(body []byte, params map[string]string) ([]byte, bool) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		body = []byte("{}")
	}
	if body[0] != '{' || !json.Valid(body) {
		return nil, false
	}
	if len(params) == 0 {
		return body, true
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, false
	}
	for k, v := range params {
		b, _ := json.Marshal(v)
		m[k] = b
	}
	out, err := json.Marshal(m)
	return out, err == nil
}

func pathParam(r *http.Request) (string, bool) {
	id := r.PathValue("id")
	return id, id != "" && len(id) <= 128
}

func (s *Server) callHandler(rt route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var params map[string]string
		if rt.param != "" {
			id, ok := pathParam(r)
			if !ok {
				writeErr(w, http.StatusBadRequest, api.CodeBadRequest, "bad id")
				return
			}
			params = map[string]string{rt.param: id}
		}
		args, ok := buildArgs(info(r).body, params)
		if !ok {
			writeErr(w, http.StatusBadRequest, api.CodeBadRequest, "body must be a JSON object")
			return
		}
		res, aerr := s.b.Call(rt.core, args)
		if aerr != nil {
			writeAPIErr(w, aerr)
			return
		}
		if len(res) == 0 {
			res = []byte("{}")
		}
		writeJSON(w, http.StatusOK, res)
	}
}

// handleQR renders the key of a keyring entry as a QR PNG (web only).
func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	id, ok := pathParam(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, api.CodeBadRequest, "bad id")
		return
	}
	args, _ := buildArgs(nil, map[string]string{"id": id})
	res, aerr := s.b.Call(api.KeyringReveal, args)
	if aerr != nil {
		writeAPIErr(w, aerr)
		return
	}
	var out struct {
		KeyText string `json:"key_text"`
	}
	if json.Unmarshal(res, &out) != nil || out.KeyText == "" || len(out.KeyText) > 256 {
		writeErr(w, http.StatusInternalServerError, api.CodeInternal, "no key text")
		return
	}
	png, err := qrcode.Encode(out.KeyText, qrcode.Medium, 320)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, api.CodeInternal, "QR encoding failed")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

// handleSession: POST exchanges a login token for a session; GET returns
// the CSRF token of the current session (the page keeps it in memory only,
// so a reload fetches it again); DELETE signs out.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if !s.auth.bucket.allow(now) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}
	switch r.Method {
	case http.MethodPost:
		if !s.originOK(r) {
			writeErr(w, http.StatusForbidden, "forbidden", "bad origin")
			return
		}
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		var req struct {
			Token string `json:"token"`
		}
		if len(body) == 0 || json.Unmarshal(body, &req) != nil {
			writeErr(w, http.StatusBadRequest, api.CodeBadRequest, "expected {\"token\":…}")
			return
		}
		if !s.auth.consume(req.Token, now) {
			writeErr(w, http.StatusUnauthorized, "bad_token", "this sign-in link has expired or was already used — open PrivateVPN from the tray icon again")
			return
		}
		cookie, csrf := s.auth.newSession(now)
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    cookie,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		b, _ := json.Marshal(map[string]string{"csrf": csrf})
		writeJSON(w, http.StatusOK, b)
	case http.MethodGet, http.MethodHead:
		sess, ok := s.auth.lookup(r, now)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "not signed in")
			return
		}
		b, _ := json.Marshal(map[string]string{"csrf": sess.csrf})
		writeJSON(w, http.StatusOK, b)
	case http.MethodDelete:
		sess, ok := s.auth.lookup(r, now)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "not signed in")
			return
		}
		if !s.originOK(r) || !csrfOK(r, sess.csrf) {
			writeErr(w, http.StatusForbidden, "forbidden", "bad origin or CSRF token")
			return
		}
		s.auth.drop(sess.key)
		http.SetCookie(w, &http.Cookie{
			Name: cookieName, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		writeJSON(w, http.StatusOK, []byte("{}"))
	default:
		w.Header().Set("Allow", "GET, HEAD, POST, DELETE")
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}
