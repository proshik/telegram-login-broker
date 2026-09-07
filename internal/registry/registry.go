// Package registry holds the only long-lived state the broker has: which bots
// exist, which applications may use them, and which slugs route webhooks.
//
// There are a few dozen records here and they change a few times a year, which
// is why this is a JSON file and not a database. Everything else the broker
// keeps is measured in minutes and lives in internal/store.
package registry

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
)

// Bot is one Telegram login bot. Its credentials never leave the broker.
type Bot struct {
	ClientID     string
	ClientSecret string
}

// Client is one registered application. Bot is optional: an empty value means
// the shared default bot, which is the common case — a private bot is only
// needed to put the right name on the consent screen.
type Client struct {
	Secret string
	Bot    string
	// RedirectOrigins are the non-loopback origins this client may be redirected
	// to. Loopback needs no entry at all; that is the point of the broker.
	RedirectOrigins []string
}

// Slug routes webhook updates for exactly one bot.
type Slug struct {
	Bot         string
	SecretToken string
	AgentToken  string
}

type Data struct {
	DefaultBot string
	Bots       map[string]Bot
	Clients    map[string]Client
	Slugs      map[string]Slug
}

// Registry serves a live snapshot: every read path goes through Snapshot or
// ResolveClient rather than through a value cached at startup, which is what
// makes runtime reconfiguration fall out for free — no SIGHUP, no reload.
type Registry struct {
	mu   sync.RWMutex
	data Data
	path string
	box  *Box
}

func (d Data) clone() Data {
	out := Data{
		DefaultBot: d.DefaultBot,
		Bots:       maps.Clone(d.Bots),
		Clients:    make(map[string]Client, len(d.Clients)),
		Slugs:      maps.Clone(d.Slugs),
	}
	for name, c := range d.Clients {
		c.RedirectOrigins = slices.Clone(c.RedirectOrigins)
		out.Clients[name] = c
	}
	if out.Bots == nil {
		out.Bots = map[string]Bot{}
	}
	if out.Slugs == nil {
		out.Slugs = map[string]Slug{}
	}
	return out
}

// Validate is the startup gate. Every rule here is one the broker would
// otherwise break silently at request time, which is worse than not starting.
func Validate(d Data) error {
	if d.DefaultBot != "" {
		if _, ok := d.Bots[d.DefaultBot]; !ok {
			return fmt.Errorf("default_bot %q is not in bots", d.DefaultBot)
		}
	}
	for name, c := range d.Clients {
		switch {
		case c.Bot != "":
			if _, ok := d.Bots[c.Bot]; !ok {
				return fmt.Errorf("client %q names bot %q, which is not in bots", name, c.Bot)
			}
		case d.DefaultBot == "":
			return fmt.Errorf("client %q has no bot and there is no default_bot", name)
		}
		for _, origin := range c.RedirectOrigins {
			if err := validateOrigin(origin); err != nil {
				return fmt.Errorf("client %q: %w", name, err)
			}
		}
	}

	// One bot is one setWebhook URL is one buffer. Two slugs sharing a bot would
	// mix two projects' updates with nothing in the update to tell them apart.
	byBot := make(map[string]string, len(d.Slugs))
	for _, name := range slices.Sorted(maps.Keys(d.Slugs)) {
		s := d.Slugs[name]
		if s.Bot == "" {
			return fmt.Errorf("slug %q names no bot", name)
		}
		if _, ok := d.Bots[s.Bot]; !ok {
			return fmt.Errorf("slug %q names bot %q, which is not in bots", name, s.Bot)
		}
		if first, taken := byBot[s.Bot]; taken {
			return fmt.Errorf("slugs %q and %q both bind bot %q; one bot can carry only one webhook", first, name, s.Bot)
		}
		byBot[s.Bot] = name
	}
	return nil
}

func validateOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("redirect origin %q is unparseable", origin)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("redirect origin %q must be http or https", origin)
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("redirect origin %q must be a bare scheme://host[:port]", origin)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("redirect origin %q must carry no path, query or fragment", origin)
	}
	if origin != strings.ToLower(origin) {
		return fmt.Errorf("redirect origin %q must be lowercase, since matching is exact", origin)
	}
	return nil
}

// Snapshot returns the live configuration by value.
func (r *Registry) Snapshot() Data {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.data.clone()
}

// ResolveClient is layer 1 of the security model: an application that is not in
// the registry is turned away here, before the broker acts on its behalf.
func (r *Registry) ResolveClient(clientID string) (Client, Bot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.data.Clients[clientID]
	if !ok {
		return Client{}, Bot{}, fmt.Errorf("client_id %q is not registered", clientID)
	}
	botName := c.Bot
	if botName == "" {
		botName = r.data.DefaultBot
	}
	bot, ok := r.data.Bots[botName]
	if !ok {
		// Validate rules this out at startup, so reaching it means the registry
		// was mutated past its own gate.
		return Client{}, Bot{}, fmt.Errorf("client %q resolves to bot %q, which is gone", clientID, botName)
	}
	return c, bot, nil
}

// Update applies a change, validates the result and persists it in one
// transaction. The snapshot is swapped only after the file is safely on disk,
// so a rejected or failed change leaves both untouched.
func (r *Registry) Update(mutate func(*Data) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := r.data.clone()
	if err := mutate(&next); err != nil {
		return err
	}
	if err := Validate(next); err != nil {
		return err
	}
	if err := save(r.path, r.box, next); err != nil {
		return err
	}
	r.data = next
	return nil
}

// EnsureClients registers or updates applications from configuration, leaving
// every client it does not name alone.
//
// It is how an application gets registered until the admin interface arrives in
// phase 7: put it in the environment and restart. Editing the file by hand is
// not an option, because the secrets in it are sealed.
func (r *Registry) EnsureClients(clients map[string]Client) error {
	if len(clients) == 0 {
		return nil
	}
	return r.Update(func(d *Data) error {
		for name, c := range clients {
			d.Clients[name] = c
		}
		return nil
	})
}
