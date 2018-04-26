package google

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	loginPath                   = "login"
	googleAuthCodeParameterName = "code"
)

func pathLogin(b *backend) *framework.Path{
	return &framework.Path{
		Pattern: loginPath,
		Fields: map[string]*framework.FieldSchema{
			googleAuthCodeParameterName: &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Google authentication code. Required.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLogin,
			logical.AliasLookaheadOperation: b.pathLoginAliasLookahead,
		},
	}
}

func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("alias lookahead")
	username := d.Get("username").(string)
	if username == "" {
		return nil, fmt.Errorf("missing username")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}, nil
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	code := data.Get(googleAuthCodeParameterName).(string)
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("missing Config"), nil
	}

	googleConfig := config.oauth2Config()
	token, err := googleConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	policies, user, groups, err := b.Login(ctx, req, token)
	if err != nil {
		return nil, err
	}

	encodedToken, err := encodeToken(token)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	resp.Auth = &logical.Auth{
		InternalData: map[string]interface{}{
			"token": encodedToken,
		},
		Policies: policies,
		Metadata: map[string]string{
			"username": user.Email,
			"domain":   user.Hd,
		},
		DisplayName: user.Email,
		LeaseOptions: logical.LeaseOptions{
			Renewable: true,
		},
		Alias: &logical.Alias{
			Name: user.Email,
		},
	}

	for _, group := range groups {
		if group == "" {
			continue
		}
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: group,
		})
	}

	return resp, nil
}

func (b *backend) authRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	encodedToken, ok := req.Auth.InternalData["token"].(string)
	if !ok {
		return nil, errors.New("no refresh token from previous login")
	}

	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("missing Config"), nil
	}

	token, err := decodeToken(encodedToken)
	if err != nil {
		return nil, err
	}

	//user, groups, err := b.authenticate(config, token)
	policies, _, groupNames, err := b.Login(ctx, req, token)
	if err != nil {
		return nil, err
	}

	if !strSliceEquals(policies, req.Auth.Policies) {
		return logical.ErrorResponse(fmt.Sprintf("policies do not match. new policies: %s. old policies: %s.", policies, req.Auth.Policies)), nil
	}

	var resp *logical.Response
	if err != nil {
		return nil, err
	}

	// Remove old aliases
	resp.Auth.GroupAliases = nil

	for _, groupName := range groupNames {
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: groupName,
		})
	}

	return resp, nil
}