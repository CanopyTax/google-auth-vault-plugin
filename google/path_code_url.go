package google

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	"golang.org/x/oauth2"
)

const (
	codeURLPath                 = "code_url"
	codeURLResponsePropertyName = "url"
)

func pathCodeURL(b *backend) *framework.Path{
	return &framework.Path{
		Pattern: codeURLPath,
		Fields:  map[string]*framework.FieldSchema{},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCodeURL,
		},
	}
}

func (b *backend) pathCodeURL(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("missing Config"), nil
	}

	authURL := config.oauth2Config().AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	return &logical.Response{
		Data: map[string]interface{}{
			codeURLResponsePropertyName: authURL,
		},
	}, nil
}
