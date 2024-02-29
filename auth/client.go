package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/common/pointerto"
	"github.com/opentelekomcloud/terraform-provider-opentelekomcloud/opentelekomcloud/helper/pathorcontents"
)

const (
	osPrefix = "OS_"
)

var validEndpoints = []string{
	"internal", "internalURL",
	"admin", "adminURL",
	"public", "publicURL",
	"",
}

type OpenTelekomCloudClient struct {
	config        *Config
	ProjectClient *golangsdk.ProviderClient
	DomainClient  *golangsdk.ProviderClient
}

func NewOpenTelekomCloudClient(cloud string) (*OpenTelekomCloudClient, error) {
	cfg := Config{
		Cloud: cloud,
	}

	client, err := cfg.LoadAndValidate()
	if err != nil {
		return nil, err
	}

	return client, err
}

type Config struct {
	AccessKey           string
	SecretKey           string
	CACertFile          string
	AllowReauth         bool
	ClientCertFile      string
	ClientKeyFile       string
	Cloud               string
	DomainID            string
	DomainName          string
	EndpointType        string
	IdentityEndpoint    string
	Insecure            bool
	Password            string
	Passcode            string
	Region              string
	Swauth              bool
	TenantID            string
	TenantName          string
	Token               string
	SecurityToken       string
	Username            string
	UserID              string
	AgencyName          string
	AgencyDomainName    string
	DelegatedProject    string
	MaxRetries          int
	MaxBackoffRetries   int
	BackoffRetryTimeout int

	UserAgent string

	environment *openstack.Env
}

func (c *Config) LoadAndValidate() (*OpenTelekomCloudClient, error) {
	if c.MaxRetries < 0 {
		return nil, fmt.Errorf("max_retries should be a positive value")
	}

	if err := c.Load(); err != nil {
		return nil, err
	}

	if c.IdentityEndpoint == "" {
		return nil, fmt.Errorf("'auth_url' must be specified")
	}

	if err := c.validateEndpoint(); err != nil {
		return nil, err
	}

	if err := c.validateProject(); err != nil {
		return nil, err
	}

	var err error
	var client *OpenTelekomCloudClient

	switch {
	case c.Token != "":
		client, err = buildClientByToken(c)
	case c.AccessKey != "" && c.SecretKey != "":
		client, err = buildClientByAKSK(c)
	case c.Password != "" && (c.Username != "" || c.UserID != ""):
		client, err = buildClientByPassword(c)
	default:
		err = fmt.Errorf("no auth means provided. Token, AK/SK or username/password are required for authentication")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate:\n%s", err)
	}

	//var osDebug bool
	//if os.Getenv("OS_DEBUG") != "" {
	//	osDebug = true
	//}

	return client, nil
}

// Load - load existing configuration from config files (`clouds.yaml`, etc.) and env variables
func (c *Config) Load() error {
	if c.environment == nil {
		c.environment = openstack.NewEnv(osPrefix)
	}
	cloud, err := c.environment.Cloud(c.Cloud)
	if err != nil {
		return err
	}

	// Auth data
	setIfEmpty(&c.Username, cloud.AuthInfo.Username)
	setIfEmpty(&c.UserID, cloud.AuthInfo.UserID)

	if c.UserID != "" {
		c.Username = ""
	}

	setIfEmpty(&c.IdentityEndpoint, cloud.AuthInfo.AuthURL)
	setIfEmpty(&c.Token, cloud.AuthInfo.Token)
	setIfEmpty(&c.Password, cloud.AuthInfo.Password)
	setIfEmpty(&c.AccessKey, cloud.AuthInfo.AccessKey)
	setIfEmpty(&c.SecretKey, cloud.AuthInfo.SecretKey)

	setIfEmpty(&c.TenantName, cloud.AuthInfo.ProjectName)
	setIfEmpty(&c.TenantID, cloud.AuthInfo.ProjectID)
	setIfEmpty(&c.DomainName, cloud.AuthInfo.DomainName)
	setIfEmpty(&c.DomainID, cloud.AuthInfo.DomainID)

	// project scope
	setIfEmpty(&c.DomainName, cloud.AuthInfo.ProjectDomainName)
	setIfEmpty(&c.DomainID, cloud.AuthInfo.ProjectDomainID)

	// user scope
	setIfEmpty(&c.DomainName, cloud.AuthInfo.UserDomainName)
	setIfEmpty(&c.DomainID, cloud.AuthInfo.UserDomainID)

	// default domain
	setIfEmpty(&c.DomainID, cloud.AuthInfo.DefaultDomain)

	// General cloud info
	setIfEmpty(&c.Region, cloud.RegionName)
	setIfEmpty(&c.CACertFile, cloud.CACertFile)
	setIfEmpty(&c.ClientCertFile, cloud.ClientCertFile)
	setIfEmpty(&c.ClientKeyFile, cloud.ClientKeyFile)
	if cloud.Verify != nil {
		c.Insecure = !*cloud.Verify
	}
	return nil
}

func (c *Config) generateTLSConfig() (*tls.Config, error) {
	config := &tls.Config{}
	if c.CACertFile != "" {
		caCert, _, err := pathorcontents.Read(c.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("error reading CA Cert: %s", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(caCert))
		config.RootCAs = caCertPool
	}

	if c.Insecure {
		config.InsecureSkipVerify = true
	}

	if c.ClientCertFile != "" && c.ClientKeyFile != "" {
		clientCert, _, err := pathorcontents.Read(c.ClientCertFile)
		if err != nil {
			return nil, fmt.Errorf("error reading Client Cert: %s", err)
		}
		clientKey, _, err := pathorcontents.Read(c.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("error reading Client Key: %s", err)
		}

		cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			return nil, err
		}

		config.Certificates = []tls.Certificate{cert}

		config.BuildNameToCertificate()
	}

	return config, nil
}

func (c *Config) validateEndpoint() error {
	for _, endpoint := range validEndpoints {
		if c.EndpointType == endpoint {
			return nil
		}
	}
	return fmt.Errorf("invalid endpoint type provided: %s", c.EndpointType)
}

// validateProject checks that `Project`(`Tenant`) value is set
func (c *Config) validateProject() error {
	if c.TenantName == "" && c.TenantID == "" && c.DelegatedProject == "" {
		return errors.New("no project name/id or delegated project is provided")
	}
	return nil
}

func (c *Config) genClients(pao, dao golangsdk.AuthOptionsProvider) (*OpenTelekomCloudClient, error) {
	pClient, err := c.genClient(pao)
	if err != nil {
		return nil, fmt.Errorf("error generating project client: %w", err)
	}

	dClient, err := c.genClient(dao)
	if err != nil {
		return nil, fmt.Errorf("error generating domain client: %w", err)
	}

	client := &OpenTelekomCloudClient{
		config:        c,
		ProjectClient: pClient,
		DomainClient:  dClient,
	}

	return client, nil
}

func (c *Config) genClient(ao golangsdk.AuthOptionsProvider) (*golangsdk.ProviderClient, error) {
	client, err := openstack.NewClient(ao.GetIdentityEndpoint())
	if err != nil {
		return nil, err
	}

	// Set UserAgent
	if strings.TrimSpace(c.UserAgent) != "" {
		client.UserAgent.Prepend(c.UserAgent)
	}

	config, err := c.generateTLSConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: config}

	// if OS_DEBUG is set, log the requests and responses
	var osDebug bool
	if os.Getenv("OS_DEBUG") != "" {
		osDebug = true
	}

	client.MaxBackoffRetries = pointerto.Int(c.MaxBackoffRetries)
	defaultBackoffTimeout := time.Duration(c.BackoffRetryTimeout) * time.Second
	client.BackoffRetryTimeout = &defaultBackoffTimeout

	client.HTTPClient = http.Client{
		Transport: &RoundTripper{
			Rt:         transport,
			OsDebug:    osDebug,
			MaxRetries: c.MaxRetries,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if client.AKSKAuthOptions.AccessKey != "" {
				golangsdk.ReSign(req, golangsdk.SignOptions{
					AccessKey: client.AKSKAuthOptions.AccessKey,
					SecretKey: client.AKSKAuthOptions.SecretKey,
				})
			}
			return nil
		},
	}

	// If using Swift Authentication, there's no need to validate authentication normally.
	if !c.Swauth {
		err = openstack.Authenticate(client, ao)
		if err != nil {
			return nil, err
		}
	}

	setIfEmpty(&c.Region, client.RegionID)

	return client, nil
}

func (c *Config) genOpenstackClient(ao golangsdk.AuthOptionsProvider) (*golangsdk.ProviderClient, error) {
	client, err := openstack.NewClient(ao.GetIdentityEndpoint())
	if err != nil {
		return nil, err
	}

	client.HTTPClient = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if client.AKSKAuthOptions.AccessKey != "" {
				golangsdk.ReSign(req, golangsdk.SignOptions{
					AccessKey: client.AKSKAuthOptions.AccessKey,
					SecretKey: client.AKSKAuthOptions.SecretKey,
				})
			}
			return nil
		},
	}

	err = openstack.Authenticate(client, ao)
	if err != nil {
		return nil, err
	}

	setIfEmpty(&c.Region, client.RegionID)

	return client, nil
}

func (c *Config) getEndpointType() golangsdk.Availability {
	if c.EndpointType == "internal" || c.EndpointType == "internalURL" {
		return golangsdk.AvailabilityInternal
	}
	if c.EndpointType == "admin" || c.EndpointType == "adminURL" {
		return golangsdk.AvailabilityAdmin
	}
	return golangsdk.AvailabilityPublic
}

// setIfEmpty set non-empty `loaded` value to empty `target` variable
func setIfEmpty(target *string, loaded string) {
	if *target == "" && loaded != "" {
		*target = loaded
	}
}

func buildClientByToken(c *Config) (*OpenTelekomCloudClient, error) {
	var pao, dao golangsdk.AuthOptions

	if c.AgencyDomainName != "" && c.AgencyName != "" {
		pao = golangsdk.AuthOptions{
			AgencyName:       c.AgencyName,
			AgencyDomainName: c.AgencyDomainName,
			DelegatedProject: c.DelegatedProject,
		}

		dao = golangsdk.AuthOptions{
			AgencyName:       c.AgencyName,
			AgencyDomainName: c.AgencyDomainName,
		}
	} else {
		pao = golangsdk.AuthOptions{
			DomainID:   c.DomainID,
			DomainName: c.DomainName,
			TenantID:   c.TenantID,
			TenantName: c.TenantName,
		}

		dao = golangsdk.AuthOptions{
			DomainID:   c.DomainID,
			DomainName: c.DomainName,
		}
	}

	for _, ao := range []*golangsdk.AuthOptions{&pao, &dao} {
		ao.IdentityEndpoint = c.IdentityEndpoint
		ao.TokenID = c.Token
	}
	return c.genClients(pao, dao)
}

func buildClientByAKSK(c *Config) (*OpenTelekomCloudClient, error) {
	var pao, dao golangsdk.AKSKAuthOptions

	if c.AgencyDomainName != "" && c.AgencyName != "" {
		pao = golangsdk.AKSKAuthOptions{
			DomainID:         c.DomainID,
			Domain:           c.DomainName,
			AgencyName:       c.AgencyName,
			AgencyDomainName: c.AgencyDomainName,
			DelegatedProject: c.DelegatedProject,
		}

		dao = golangsdk.AKSKAuthOptions{
			DomainID:         c.DomainID,
			Domain:           c.DomainName,
			AgencyName:       c.AgencyName,
			AgencyDomainName: c.AgencyDomainName,
		}
	} else {
		pao = golangsdk.AKSKAuthOptions{
			ProjectName: c.TenantName,
			ProjectId:   c.TenantID,
		}

		dao = golangsdk.AKSKAuthOptions{
			DomainID: c.DomainID,
			Domain:   c.DomainName,
		}
	}
	if c.SecurityToken != "" {
		dao.ProjectId = c.TenantID
		dao.ProjectName = c.TenantName
	}
	for _, ao := range []*golangsdk.AKSKAuthOptions{&pao, &dao} {
		ao.IdentityEndpoint = c.IdentityEndpoint
		ao.AccessKey = c.AccessKey
		ao.SecretKey = c.SecretKey
		if c.SecurityToken != "" {
			ao.SecurityToken = c.SecurityToken
		}
	}
	return c.genClients(pao, dao)
}

func buildClientByPassword(c *Config) (*OpenTelekomCloudClient, error) {
	var pao, dao golangsdk.AuthOptions

	if c.AgencyDomainName != "" && c.AgencyName != "" {
		pao = golangsdk.AuthOptions{
			DomainID:         c.DomainID,
			DomainName:       c.DomainName,
			AgencyName:       c.AgencyName,
			AgencyDomainName: c.AgencyDomainName,
			DelegatedProject: c.DelegatedProject,
		}

		dao = golangsdk.AuthOptions{
			DomainID:         c.DomainID,
			DomainName:       c.DomainName,
			AgencyName:       c.AgencyName,
			AgencyDomainName: c.AgencyDomainName,
		}
	} else {
		pao = golangsdk.AuthOptions{
			DomainID:   c.DomainID,
			DomainName: c.DomainName,
			TenantID:   c.TenantID,
			TenantName: c.TenantName,
		}

		dao = golangsdk.AuthOptions{
			DomainID:   c.DomainID,
			DomainName: c.DomainName,
		}
	}

	for _, ao := range []*golangsdk.AuthOptions{&pao, &dao} {
		ao.IdentityEndpoint = c.IdentityEndpoint
		ao.Password = c.Password
		ao.Username = c.Username
		ao.UserID = c.UserID
		ao.Passcode = c.Passcode
		ao.AllowReauth = c.AllowReauth
	}

	return c.genClients(pao, dao)
}
