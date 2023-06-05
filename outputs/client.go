package outputs

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	crdClient "github.com/kubernetes-sigs/wg-policy-prototypes/policy-report/kube-bench-adapter/pkg/generated/v1alpha2/clientset/versioned"
	"github.com/rs/zerolog"

	gcpfunctions "cloud.google.com/go/functions/apiv1"
	"github.com/streadway/amqp"
	wavefront "github.com/wavefronthq/wavefront-sdk-go/senders"

	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/aws/aws-sdk-go/aws/session"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/segmentio/kafka-go"
	"k8s.io/client-go/kubernetes"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	timescaledb "github.com/jackc/pgx/v5/pgxpool"
	redis "github.com/redis/go-redis/v9"

	"github.com/falcosecurity/falcosidekick/types"
)

// ErrHeaderMissing = 400
var ErrHeaderMissing = errors.New("header missing")

// ErrClientAuthenticationError = 401
var ErrClientAuthenticationError = errors.New("authentication error")

// ErrForbidden = 403
var ErrForbidden = errors.New("access denied")

// ErrNotFound = 404
var ErrNotFound = errors.New("resource not found")

// ErrUnprocessableEntityError = 422
var ErrUnprocessableEntityError = errors.New("bad request")

// ErrTooManyRequest = 429
var ErrTooManyRequest = errors.New("exceeding post rate limit")

// ErrInternalServer = 500
var ErrInternalServer = errors.New("internal server error")

// ErrBadGateway = 502
var ErrBadGateway = errors.New("bad gateway")

// ErrClientCreation is returned if client can't be created
var ErrClientCreation = errors.New("client creation error")

var ErrSASLAuthCreation = errors.New("sasl auth: wrong mechanism")

// EnabledOutputs list all enabled outputs
var EnabledOutputs []string

// DefaultContentType is the default Content-Type header to send along with the Client's POST Request
const DefaultContentType = "application/json; charset=utf-8"

// Some common header values that may be needed in other files
const ContentTypeHeaderKey = "Content-Type"
const UserAgentHeaderKey = "User-Agent"
const AuthorizationHeaderKey = "Authorization"
const UserAgentHeaderValue = "Falcosidekick"

// files names are static fo the shake of helm and single docker compatibility
const MutualTLSClientCertFilename = "/client.crt"
const MutualTLSClientKeyFilename = "/client.key"
const MutualTLSCacertFilename = "/ca.crt"

// HTTP Methods
const HttpPost = "POST"
const HttpPut = "PUT"

// Headers to add to the client before sending the request
type Header struct {
	Key   string
	Value string
}

// Client communicates with the different API.
type Client struct {
	OutputType              string
	EndpointURL             *url.URL
	MutualTLSEnabled        bool
	CheckCert               bool
	HeaderList              []Header
	ContentType             string
	Config                  *types.Configuration
	Stats                   *types.Statistics
	PromStats               *types.PromStatistics
	AWSSession              *session.Session
	StatsdClient            *statsd.Client
	DogstatsdClient         *statsd.Client
	GCPTopicClient          *pubsub.Topic
	GCPCloudFunctionsClient *gcpfunctions.CloudFunctionsClient
	// FIXME: this lock requires a per-output usage lock currently if headers are used -- needs to be refactored
	httpClientLock sync.Mutex

	GCSStorageClient  *storage.Client
	KafkaProducer     *kafka.Writer
	CloudEventsClient cloudevents.Client
	KubernetesClient  kubernetes.Interface
	RabbitmqClient    *amqp.Channel
	WavefrontSender   *wavefront.Sender
	Crdclient         *crdClient.Clientset
	MQTTClient        mqtt.Client
	TimescaleDBClient *timescaledb.Pool
	RedisClient       *redis.Client

	logging *zerolog.Logger
}

// NewClient returns a new output.Client for accessing the different API.
func NewClient(outputType string, defaultEndpointURL string, mutualTLSEnabled bool, checkCert bool, config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client, logging *zerolog.Logger) (*Client, error) {
	reg := regexp.MustCompile(`(http|nats)(s?)://.*`)
	if !reg.MatchString(defaultEndpointURL) {
		logging.Error().Err(fmt.Errorf("%s", "Bad Endpoint")).Str("output-type", outputType).Msg("")
		return nil, ErrClientCreation
	}
	if _, err := url.ParseRequestURI(defaultEndpointURL); err != nil {
		logging.Error().Err(err).Str("output-type", outputType).Msg("")
		return nil, ErrClientCreation
	}
	endpointURL, err := url.Parse(defaultEndpointURL)
	if err != nil {
		logging.Error().Err(err).Str("output-type", outputType).Msg("")
		return nil, ErrClientCreation
	}
	return &Client{OutputType: outputType, EndpointURL: endpointURL, MutualTLSEnabled: mutualTLSEnabled, CheckCert: checkCert, HeaderList: []Header{}, ContentType: DefaultContentType, Config: config, Stats: stats, PromStats: promStats, StatsdClient: statsdClient, DogstatsdClient: dogstatsdClient}, nil
}

// Post sends event (payload) to Output with POST http method.
func (c *Client) Post(payload interface{}) error {
	return c.sendRequest("POST", payload)
}

// Put sends event (payload) to Output with PUT http method.
func (c *Client) Put(payload interface{}) error {
	return c.sendRequest("PUT", payload)
}

// Post sends event (payload) to Output.
func (c *Client) sendRequest(method string, payload interface{}) error {
	// defer + recover to catch panic if output doesn't respond
	defer func() {
		if err := recover(); err != nil {
			c.logging.Error().Err(fmt.Errorf("%v", err)).Str("output-type", c.OutputType).Msg("")
		}
	}()

	body := new(bytes.Buffer)
	switch payload.(type) {
	case influxdbPayload:
		fmt.Fprintf(body, "%v", payload)
		if c.Config.Debug {
			c.logging.Debug().Str("output-type", c.OutputType).Str("payload", body.String()).Msg("")
		}
	case spyderbatPayload:
		zipper := gzip.NewWriter(body)
		if err := json.NewEncoder(zipper).Encode(payload); err != nil {
			c.logging.Error().Err(fmt.Errorf("%v", err)).Str("output-type", c.OutputType).Msg("")
		}
		zipper.Close()
		if c.Config.Debug {
			debugBody := new(bytes.Buffer)
			if err := json.NewEncoder(debugBody).Encode(payload); err == nil {
				c.logging.Debug().Str("output-type", c.OutputType).Str("payload", debugBody.String()).Msg("")
			}
		}
	default:
		if err := json.NewEncoder(body).Encode(payload); err != nil {
			c.logging.Error().Err(err).Msgf("")
		}
		if c.Config.Debug {
			c.logging.Debug().Str("output-type", c.OutputType).Str("payload", body.String()).Msg("")
		}
	}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()

	if c.MutualTLSEnabled {
		// Load client cert
		var MutualTLSClientCertPath, MutualTLSClientKeyPath, MutualTLSClientCaCertPath string
		if c.Config.MutualTLSClient.CertFile != "" {
			MutualTLSClientCertPath = c.Config.MutualTLSClient.CertFile
		} else {
			MutualTLSClientCertPath = c.Config.MutualTLSFilesPath + MutualTLSClientCertFilename
		}
		if c.Config.MutualTLSClient.KeyFile != "" {
			MutualTLSClientKeyPath = c.Config.MutualTLSClient.KeyFile
		} else {
			MutualTLSClientKeyPath = c.Config.MutualTLSFilesPath + MutualTLSClientKeyFilename
		}
		if c.Config.MutualTLSClient.CaCertFile != "" {
			MutualTLSClientCaCertPath = c.Config.MutualTLSClient.CaCertFile
		} else {
			MutualTLSClientCaCertPath = c.Config.MutualTLSFilesPath + MutualTLSCacertFilename
		}
		cert, err := tls.LoadX509KeyPair(MutualTLSClientCertPath, MutualTLSClientKeyPath)
		if err != nil {
			c.logging.Error().Err(err).Msgf("")
		}

		// Load CA cert
		caCert, err := ioutil.ReadFile(MutualTLSClientCaCertPath)
		if err != nil {
			c.logging.Error().Err(err).Msgf("")
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		customTransport.TLSClientConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		// With MutualTLS enabled, the check cert flag is ignored
		if !c.CheckCert {
			// #nosec G402 This is only set as a result of explicit configuration
			customTransport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
	}
	client := &http.Client{
		Transport: customTransport,
	}

	req, err := http.NewRequest(method, c.EndpointURL.String(), body)
	if err != nil {
		c.logging.Error().Err(err).Msgf("")
	}

	req.Header.Add(ContentTypeHeaderKey, c.ContentType)
	req.Header.Add(UserAgentHeaderKey, UserAgentHeaderValue)

	for _, headerObj := range c.HeaderList {
		req.Header.Add(headerObj.Key, headerObj.Value)
	}

	resp, err := client.Do(req)
	if err != nil {
		c.logging.Error().Err(err).Msgf("")
		go c.CountMetric("outputs", 1, []string{"output:" + strings.ToLower(c.OutputType), "status:connectionrefused"})
		return err
	}
	defer resp.Body.Close()

	// Clear out headers - they will be set for the next request.
	c.HeaderList = []Header{}
	go c.CountMetric("outputs", 1, []string{"output:" + strings.ToLower(c.OutputType), "status:" + strings.ToLower(http.StatusText(resp.StatusCode))})

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent: //200, 201, 202, 204
		c.logging.Info().Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Msgf("Post Ok")
		body, _ := ioutil.ReadAll(resp.Body)
		if ot := c.OutputType; ot == Kubeless || ot == Openfaas || ot == Fission {
			c.logging.Info().Str("output-type", ot).Str("payload", string(body)).Msg("Function response")
		}
		return nil
	case http.StatusBadRequest: //400
		body, _ := ioutil.ReadAll(resp.Body)
		c.logging.Error().Err(ErrHeaderMissing).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Str("payload", string(body)).Msg("")
		return ErrHeaderMissing
	case http.StatusUnauthorized: //401
		body, _ := ioutil.ReadAll(resp.Body)
		c.logging.Error().Err(ErrClientAuthenticationError).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Str("payload", string(body)).Msg("")
		return ErrClientAuthenticationError
	case http.StatusForbidden: //403
		body, _ := ioutil.ReadAll(resp.Body)
		c.logging.Error().Err(ErrForbidden).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Str("payload", string(body)).Msg("")
		return ErrForbidden
	case http.StatusNotFound: //404
		body, _ := ioutil.ReadAll(resp.Body)
		c.logging.Error().Err(ErrNotFound).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Str("payload", string(body)).Msg("")
		return ErrNotFound
	case http.StatusUnprocessableEntity: //422
		body, _ := ioutil.ReadAll(resp.Body)
		c.logging.Error().Err(ErrUnprocessableEntityError).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Str("payload", string(body)).Msg("")
		return ErrUnprocessableEntityError
	case http.StatusTooManyRequests: //429
		body, _ := ioutil.ReadAll(resp.Body)
		c.logging.Error().Err(ErrTooManyRequest).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Str("payload", string(body)).Msg("")
		return ErrTooManyRequest
	case http.StatusInternalServerError: //500
		c.logging.Error().Err(ErrTooManyRequest).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Msg("")
		return ErrInternalServer
	case http.StatusBadGateway: //502
		c.logging.Error().Err(ErrTooManyRequest).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Msg("")
		return ErrBadGateway
	default:
		c.logging.Error().Err(fmt.Errorf("Unexpected response")).Str("output-type", c.OutputType).Int("response-status-code", resp.StatusCode).Msg("")
		return errors.New(resp.Status)
	}
}

// BasicAuth adds an HTTP Basic Authentication compliant header to the Client.
func (c *Client) BasicAuth(username, password string) {
	// Check out RFC7617 for the specifics on this code.
	// https://datatracker.ietf.org/doc/html/rfc7617
	// This might break I18n, but we can cross that bridge when we come to it.
	userPass := username + ":" + password
	b64UserPass := base64.StdEncoding.EncodeToString([]byte(userPass))
	c.AddHeader(AuthorizationHeaderKey, "Basic "+b64UserPass)
}

// AddHeader adds an HTTP Header to the Client.
func (c *Client) AddHeader(key, value string) {
	c.HeaderList = append(c.HeaderList, Header{Key: key, Value: value})
}
