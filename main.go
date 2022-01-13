package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	//"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager-webhook-example/internal"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
)

// GroupName is the unique name
var (
	GroupName       = os.Getenv("GROUP_NAME")
	domainID  int64 = os.Getenv("DOMAIN_ID")
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	//client kubernetes.Clientset
	config  *Config
	client  *internal.Client
	MongoDB *mongo.Database
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	// APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
	// Username        string                     `json:"username"`
	AuthAPIKey    string `json:"authApiKey"`
	AuthAPISecret string `json:"authApiSecret"`
	MongoURL      string `json:"mongoURL"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "constellix"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := c.setupConfig(ch)
	if err != nil {
		return err
	}

	// TODO: do something more useful with the decoded configuration
	fmt.Printf("Decoded configuration %v", cfg)

	// TODO: add code that sets a record in the DNS provider's console

	// find the username for the domain
	domain, err := c.findUsername(ch.DNSName)
	if err != nil {
		return err
	}

	// Get all the TXT records for adspentraak.com
	records, err := c.client.TxtRecords.GetAll(domainID)
	if err != nil {
		return err
	}

	// find the TXT record for the username
	record := findRecords(records, domain.Username)

	// TXT record entry already existing
	if record != nil {
		if containsValue(record, ch.Key) {
			return nil
		}

		request := internal.RecordRequest{
			Name:       record.Name,
			TTL:        record.TTL,
			RoundRobin: append(record.RoundRobin, internal.RecordValue{Value: fmt.Sprintf(`"%s"`, ch.Key)}),
		}

		// Update the record
		_, err = c.client.TxtRecords.Update(domainID, record.ID, request)
		if err != nil {
			return fmt.Errorf("constellix: failed to update TXT records: %w", err)
		}
		return nil
	}

	// Prep the new TXT record
	request := internal.RecordRequest{
		Name: domain.Username,
		TTL:  c.config.TTL,
		RoundRobin: []internal.RecordValue{
			{Value: fmt.Sprintf(`"%s"`, ch.Key)},
		},
	}

	_, err = c.client.TxtRecords.Create(domainID, request)
	if err != nil {
		return fmt.Errorf("constellix: failed to create TXT record %s: %w", ch.DNSName, err)
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// TODO: add code that deletes a record from the DNS provider's console
	_, err := c.setupConfig(ch)
	if err != nil {
		return err
	}

	// find the username for the domain
	domain, err := c.findUsername(ch.DNSName)
	if err != nil {
		return err
	}

	// Get all the TXT records for adspentraak.com
	records, err := c.client.TxtRecords.GetAll(domainID)
	if err != nil {
		return err
	}

	record := findRecords(records, domain.Username)
	if record == nil {
		return nil
	}

	// Check if key exists in the TXT record
	if !containsValue(record, ch.Key) {
		return nil
	}

	// only 1 record value, the whole record must be deleted.
	if len(record.Value) == 1 {
		_, err = c.client.TxtRecords.Delete(domainID, record.ID)
		if err != nil {
			return fmt.Errorf("constellix: failed to delete TXT records: %w", err)
		}
		return nil
	}

	// Otherwise just remove the one value
	request := internal.RecordRequest{
		Name: record.Name,
		TTL:  record.TTL,
	}

	for _, val := range record.Value {
		if val.Value != fmt.Sprintf(`"%s"`, ch.Key) {
			request.RoundRobin = append(request.RoundRobin, val)
		}
	}

	_, err = c.client.TxtRecords.Update(domainID, record.ID, request)
	if err != nil {
		return fmt.Errorf("constellix: failed to update TXT records: %w", err)
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	// cl, err := kubernetes.NewForConfig(kubeClientConfig)
	// if err != nil {
	// 	return err
	// }

	// c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// SetupConfig loads the config from the clusterissuer and sets up mongodb connection
func (c *customDNSProviderSolver) setupConfig(ch *v1alpha1.ChallengeRequest) (*customDNSProviderConfig, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	// Setup the constellix connection
	c.config = NewDefaultConfig()
	c.config.APIKey = cfg.AuthAPIKey
	c.config.SecretKey = cfg.AuthAPISecret

	if c.config.SecretKey == "" || c.config.APIKey == "" {
		return nil, errors.New("constellix: incomplete credentials, missing secret key and/or API key")
	}

	tr, err := internal.NewTokenTransport(c.config.APIKey, c.config.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("constellix: %w", err)
	}

	c.client = internal.NewClient(tr.Wrap(c.config.HTTPClient))

	// Setup the Mongodb Connection
	mc, err := MongoClient(cfg.MongoURL)
	if err != nil {
		return nil, err
	}
	c.MongoDB = mc.Database("adspen_domain")

	return &cfg, nil
}

func (c *customDNSProviderSolver) findUsername(dnsName string) (*UsernameSchema, error) {
	// if its our domain then username is the acme challenge
	if dnsName == "*.adspentraak.com" || dnsName == "adspentraak.com" {
		return &UsernameSchema{Username: "_acme-challenge"}, nil
	}

	// check mongo for the username
	collection := c.MongoDB.Collection("records")

	// search mongo for the lander filter
	cur, err := collection.Aggregate(context.TODO(), []bson.M{
		bson.M{
			"$match": bson.M{
				"domain": dnsName,
			},
		},
		bson.M{
			"$lookup": bson.M{
				"from":         "records",
				"localField":   "owner",
				"foreignField": "owner",
				"as":           "recordList",
			},
		},
		bson.M{
			"$unwind": bson.M{
				"path": "$recordList",
			},
		},
		bson.M{
			"$project": bson.M{
				"username": "$recordList.username",
				"owner":    "$owner",
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("mongodb aggregation error: %w", err)
	}

	var results UsernameSchema
	for cur.Next(context.TODO()) {
		// decode to a mongodb schema
		err := cur.Decode(&results)

		if err != nil {
			return nil, fmt.Errorf("mongodb decoding error: %w", err)
		}
	}

	if err := cur.Err(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	cur.Close(context.TODO())

	return &results, nil
}

// UsernameSchema is a mongodb response
type UsernameSchema struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username,omitempty"`
	Owner    string             `bson:"owner,omitempty"`
}

// Config is used to configure the creation of the DNSProvider
type Config struct {
	APIKey             string
	SecretKey          string
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
	HTTPClient         *http.Client
}

// NewDefaultConfig returns a default configuration for the DNSProvider
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                300,
		PropagationTimeout: 60 * time.Second,
		PollingInterval:    2 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// MongoClient returns a mongodb client
func MongoClient(uri string) (*mongo.Client, error) {
	clientOptions := options.Client().ApplyURI(uri)

	// connect to mongodb
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return nil, fmt.Errorf("mongo connection: %w", err)
	}

	// check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, fmt.Errorf("mongo connection not avail: %w", err)
	}

	return client, nil
}

func findRecords(records []internal.Record, name string) *internal.Record {
	for _, r := range records {
		if r.Name == name {
			return &r
		}
	}

	return nil
}

func containsValue(record *internal.Record, value string) bool {
	for _, val := range record.Value {
		if val.Value == fmt.Sprintf(`"%s"`, value) {
			return true
		}
	}

	return false
}
