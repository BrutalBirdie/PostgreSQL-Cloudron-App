// Package directory reads Cloudron users and groups from the SCIM addon. It
// only lists users who may access this app and groups allowed for it.
// https://docs.cloudron.io/packaging/addons#scim
package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"pgpanel/internal/access"
)

var ErrNotConfigured = errors.New("the SCIM addon is not configured")

type User struct {
	Username    string
	DisplayName string
	GroupIDs    []string
	GroupNames  []string
}

func (u User) Member() access.Member {
	return access.Member{Username: u.Username, GroupIDs: u.GroupIDs, GroupNames: u.GroupNames}
}

type Group struct {
	ID   string
	Name string
}

type Client struct {
	origin string
	token  string
	ttl    time.Duration
	http   *http.Client

	mu        sync.Mutex
	users     map[string]cachedUser
	listAt    time.Time
	listUsers []User
	listGroup []Group
}

type cachedUser struct {
	user *User // nil when the user does not exist or has no access to the app
	at   time.Time
}

// New returns nil when the addon is not configured; a nil client reports
// ErrNotConfigured.
func New(origin, token string, ttl time.Duration) *Client {
	if origin == "" || token == "" {
		return nil
	}
	return &Client{origin: strings.TrimRight(origin, "/"), token: token, ttl: ttl, http: &http.Client{Timeout: 10 * time.Second}, users: map[string]cachedUser{}}
}

type scimUser struct {
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
	Groups      []struct {
		Value   string `json:"value"`
		Display string `json:"display"`
	} `json:"groups"`
}

type scimGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type listResponse[T any] struct {
	TotalResults int `json:"totalResults"`
	Resources    []T `json:"Resources"`
}

func (u scimUser) toUser() User {
	out := User{Username: u.UserName, DisplayName: u.DisplayName}
	for _, g := range u.Groups {
		out.GroupIDs = append(out.GroupIDs, g.Value)
		out.GroupNames = append(out.GroupNames, g.Display)
	}
	return out
}

func get[T any](ctx context.Context, c *Client, path string, query url.Values) (listResponse[T], error) {
	var out listResponse[T]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path+"?"+query.Encode(), nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/scim+json, application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return out, fmt.Errorf("SCIM %s: HTTP %d", path, res.StatusCode)
	}
	return out, json.NewDecoder(res.Body).Decode(&out)
}

func listAll[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	for start := 1; ; {
		page, err := get[T](ctx, c, path, url.Values{"startIndex": {fmt.Sprint(start)}, "count": {"100"}})
		if err != nil {
			return nil, err
		}
		all = append(all, page.Resources...)
		start += len(page.Resources)
		if len(page.Resources) == 0 || len(all) >= page.TotalResults {
			return all, nil
		}
	}
}

// Lookup returns the user and their groups, nil when the user does not exist
// or may not access the app. On a SCIM error the last known answer is
// returned together with the error, never a guess.
func (c *Client) Lookup(ctx context.Context, username string) (*User, error) {
	if c == nil {
		return nil, ErrNotConfigured
	}
	c.mu.Lock()
	cached, ok := c.users[username]
	c.mu.Unlock()
	if ok && time.Since(cached.at) < c.ttl {
		return cached.user, nil
	}
	filter := fmt.Sprintf(`userName eq "%s"`, strings.ReplaceAll(username, `"`, ""))
	res, err := get[scimUser](ctx, c, "/v2/Users", url.Values{"filter": {filter}})
	if err != nil {
		if ok {
			return cached.user, err
		}
		return nil, err
	}
	var user *User
	for _, u := range res.Resources {
		if u.UserName == username && u.Active {
			v := u.toUser()
			user = &v
		}
	}
	c.mu.Lock()
	c.users[username] = cachedUser{user: user, at: time.Now()}
	c.mu.Unlock()
	return user, nil
}

// Directory lists all users and groups that may access the app, for the owner picker.
func (c *Client) Directory(ctx context.Context) ([]User, []Group, error) {
	if c == nil {
		return nil, nil, ErrNotConfigured
	}
	c.mu.Lock()
	if time.Since(c.listAt) < c.ttl {
		users, groups := c.listUsers, c.listGroup
		c.mu.Unlock()
		return users, groups, nil
	}
	c.mu.Unlock()
	rawUsers, err := listAll[scimUser](ctx, c, "/v2/Users")
	if err != nil {
		return nil, nil, err
	}
	rawGroups, err := listAll[scimGroup](ctx, c, "/v2/Groups")
	if err != nil {
		return nil, nil, err
	}
	var users []User
	for _, u := range rawUsers {
		if u.Active && u.UserName != "" {
			users = append(users, u.toUser())
		}
	}
	groups := make([]Group, 0, len(rawGroups))
	for _, g := range rawGroups {
		groups = append(groups, Group{ID: g.ID, Name: g.DisplayName})
	}
	c.mu.Lock()
	c.listAt, c.listUsers, c.listGroup = time.Now(), users, groups
	c.mu.Unlock()
	return users, groups, nil
}

// GroupByName resolves a group name typed by an admin to its id.
func (c *Client) GroupByName(ctx context.Context, name string) (*Group, error) {
	_, groups, err := c.Directory(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if strings.EqualFold(g.Name, name) {
			return &g, nil
		}
	}
	return nil, nil
}
