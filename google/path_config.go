package google

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	configPath                     = "config"
	clientIDConfigPropertyName     = "client_id"
	clientSecretConfigPropertyName = "client_secret"
	fetchGroupsConfigPropertyName  = "fetch_groups"
	configEntry                    = "config"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: configPath,
		Fields: map[string]*framework.FieldSchema{
			clientIDConfigPropertyName: {
				Type:        framework.TypeString,
				Description: "Google application ID",
			},
			clientSecretConfigPropertyName: {
				Type:        framework.TypeString,
				Description: "Google application secret",
			},
			fetchGroupsConfigPropertyName: {
				Type:		framework.TypeBool,
				Description: "Fetch groups for binding Google group to Vault policy",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigWrite,
			logical.ReadOperation:   b.pathConfigRead,
		},
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var (
		clientID     = data.Get(clientIDConfigPropertyName).(string)
		clientSecret = data.Get(clientSecretConfigPropertyName).(string)
		fetchGroups  = data.Get(fetchGroupsConfigPropertyName).(bool)
	)

	entry, err := logical.StorageEntryJSON(configEntry, Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		FetchGroups:  fetchGroups,
	})
	if err != nil {
		return nil, err
	}

	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	configMap := map[string]interface{}{
		clientIDConfigPropertyName:     config.ClientID,
		clientSecretConfigPropertyName: config.ClientSecret,
		fetchGroupsConfigPropertyName:	config.FetchGroups,
	}

	return &logical.Response{
		Data: configMap,
	}, nil
}

// Config returns the configuration for this backend.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*Config, error) {
	entry, err := s.Get(ctx, configEntry)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result Config
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("error reading configuration: %s", err)
	}

	return &result, nil
}

type Config struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	FetchGroups  bool   `json:"fetch_groups"`
}

func (c *Config) oauth2Config() *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
	}
	if c.FetchGroups {
		config.Scopes = append(config.Scopes, "https://www.googleapis.com/auth/admin.directory.group.readonly")
	}
	return config
}
