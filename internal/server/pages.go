package server

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/proshik/telegram-login-broker/internal/config"
)

// Embedded, not read from disk: the production image is distroless, where there
// is neither a filesystem to hold these nor a shell to work out why they are
// missing.
//
//go:embed templates/*.html
var templateFS embed.FS

// Every page defines the same "title" and "body" blocks, so they are parsed into
// one template set each rather than into a single shared set, where the last
// file parsed would silently win for all of them.
var pages = func() map[string]*template.Template {
	out := map[string]*template.Template{}
	for _, name := range []string{"chooser.html", "error.html", "refused.html", "index.html"} {
		out[name] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+name))
	}
	return out
}()

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The broker's own pages need no scripts and load nothing from anywhere.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	page, ok := pages[name]
	if !ok {
		s.opts.Logger.Error("no such page", "template", name)
		return
	}
	if err := page.ExecuteTemplate(w, "layout", data); err != nil {
		s.opts.Logger.Error("cannot render page", "template", name, "err", err)
	}
}

// refuse answers on a page of the broker's own. It never sets Location: at the
// point any of these fire, the redirect_uri is either unvalidated or irrelevant,
// and bouncing the browser somewhere to report the problem is how an open
// redirect gets built by accident.
func (s *Server) refuse(w http.ResponseWriter, _ *http.Request, status int, reason string) {
	s.render(w, status, "error.html", map[string]any{"Reason": reason})
}

func (s *Server) renderRefused(w http.ResponseWriter) {
	s.render(w, http.StatusForbidden, "refused.html", nil)
}

func (s *Server) renderChooser(w http.ResponseWriter, flow string) {
	s.render(w, http.StatusOK, "chooser.html", map[string]any{
		"Flow":  flow,
		"Users": s.opts.Config.MockUsers,
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	mode := "telegram"
	if s.opts.Config.MockEnabled {
		mode = "mock"
	}
	var users []config.MockUser
	if s.opts.Config.MockEnabled {
		users = s.opts.Config.MockUsers
	}
	s.render(w, http.StatusOK, "index.html", map[string]any{
		"Mode":     mode,
		"Issuer":   s.opts.Config.Issuer,
		"Callback": s.callbackURL(),
		"Users":    users,
	})
}
