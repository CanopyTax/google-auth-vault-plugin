package google

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"fmt"
	"golang.org/x/oauth2"
	goauth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/admin/directory/v1"
	"strings"
)

// Factory for Google backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

const googleBackendHelp = `
The Google credential provider allows you to authenticate with Google.

Documentation can be found at https://github.com/grapeshot/google-auth-vault-plugin.
`

// Backend for google
func newBackend() *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.authRenew,
		Help:        googleBackendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				loginPath,
				codeURLPath,
			},
		},

		Paths: append([]*framework.Path{
			pathConfig(&b),
			pathLogin(&b),
			pathCodeURL(&b),
			pathGroups(&b),
			pathGroupsList(&b),
			pathUsers(&b),
			pathUsersList(&b),
		}),
	}

	return &b
}

func (b *backend) Login(ctx context.Context, req *logical.Request, token *oauth2.Token) ([]string, *goauth.Userinfoplus, []string, error) {
	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, nil, nil, err
	}
	if cfg == nil {
		return nil, nil, nil, fmt.Errorf("google backend not configured")
	}

	client := cfg.oauth2Config().Client(context.Background(), token)
	userService, err := goauth.New(client)
	if err != nil {
		return nil, nil, nil, err
	}

	user, err := goauth.NewUserinfoV2MeService(userService).Get().Do()
	if err != nil {
		return nil, nil, nil, err
	}

	var groups []string
	// Import the custom added groups from google backend
	userEntry, err := b.User(ctx, req.Storage, user.Email)
	if err == nil && userEntry != nil && userEntry.Groups != nil {
		if b.Logger().IsDebug() {
			b.Logger().Debug("auth/google: adding local groups", "num_local_groups", len(userEntry.Groups), "local_groups", userEntry.Groups)
		}
		groups = append(groups, userEntry.Groups...)
	}

	if cfg.FetchGroups {
		groupsService, err := admin.New(client)
		if err != nil {
			return nil, nil, nil, err
		}

		request := groupsService.Groups.List()
		request.UserKey(user.Email)
		response, err := request.Do()
		if err != nil {
			return nil, nil, nil, err
		}

		for _, group := range response.Groups {
			groups = append(groups, friendlyName(group.Email))
		}
	}

	// Retrieve policies
	var policies []string
	for _, groupName := range groups {
		group, err := b.Group(ctx, req.Storage, groupName)
		if err == nil && group != nil {
			policies = append(policies, group.Policies...)
		}
	}

	return policies, user, groups, nil
}

func friendlyName(s string) string {
	return strings.Split(s, "@")[0]
}

type backend struct {
	*framework.Backend
}
