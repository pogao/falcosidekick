package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
<<<<<<< HEAD
	"io/ioutil"
	"log"
=======
>>>>>>> 1d81920 (Modify code to use Zerolog as new logger)
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/embano1/memlog"
	"github.com/rs/zerolog"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/falcosecurity/falcosidekick/outputs"
	"github.com/falcosecurity/falcosidekick/types"
)

// Globale variables
var (
	nullClient          *outputs.Client
	slackClient         *outputs.Client
	cliqClient          *outputs.Client
	rocketchatClient    *outputs.Client
	mattermostClient    *outputs.Client
	teamsClient         *outputs.Client
	datadogClient       *outputs.Client
	discordClient       *outputs.Client
	alertmanagerClient  *outputs.Client
	elasticsearchClient *outputs.Client
	influxdbClient      *outputs.Client
	lokiClient          *outputs.Client
	natsClient          *outputs.Client
	stanClient          *outputs.Client
	awsClient           *outputs.Client
	smtpClient          *outputs.Client
	opsgenieClient      *outputs.Client
	webhookClient       *outputs.Client
	noderedClient       *outputs.Client
	cloudeventsClient   *outputs.Client
	azureClient         *outputs.Client
	gcpClient           *outputs.Client
	googleChatClient    *outputs.Client
	kafkaClient         *outputs.Client
	kafkaRestClient     *outputs.Client
	pagerdutyClient     *outputs.Client
	gcpCloudRunClient   *outputs.Client
	kubelessClient      *outputs.Client
	openfaasClient      *outputs.Client
	tektonClient        *outputs.Client
	webUIClient         *outputs.Client
	policyReportClient  *outputs.Client
	rabbitmqClient      *outputs.Client
	wavefrontClient     *outputs.Client
	fissionClient       *outputs.Client
	grafanaClient       *outputs.Client
	grafanaOnCallClient *outputs.Client
	yandexClient        *outputs.Client
	syslogClient        *outputs.Client
	mqttClient          *outputs.Client
	zincsearchClient    *outputs.Client
	gotifyClient        *outputs.Client
	spyderbatClient     *outputs.Client
	timescaleDBClient   *outputs.Client
	redisClient         *outputs.Client
	telegramClient      *outputs.Client
	n8nClient           *outputs.Client
	openObserveClient   *outputs.Client

	statsdClient, dogstatsdClient *statsd.Client
	config                        *types.Configuration
	stats                         *types.Statistics
	promStats                     *types.PromStatistics
	logging                       *zerolog.Logger

	regPromLabels *regexp.Regexp
)

func init() {
	// detect unit testing and skip init.
	// see: https://github.com/alecthomas/kingpin/issues/187
	testing := (strings.HasSuffix(os.Args[0], ".test") ||
		strings.HasSuffix(os.Args[0], "__debug_bin"))
	if testing {
		return
	}

	regPromLabels, _ = regexp.Compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")

	config = getConfig()
	stats = getInitStats()
	promStats = getInitPromStats(config)

	logging = getLogger(config.Debug)

	nullClient = &outputs.Client{
		OutputType:      "null",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}

	if config.Statsd.Forwarder != "" {
		var err error
		statsdClient, err = outputs.NewStatsdClient("StatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "StatsD")
			nullClient.DogstatsdClient = statsdClient
		}
	}

	if config.Dogstatsd.Forwarder != "" {
		var err error
		dogstatsdClient, err = outputs.NewStatsdClient("DogStatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "DogStatsD")
			nullClient.DogstatsdClient = dogstatsdClient
		}
	}

	if config.Slack.WebhookURL != "" {
		var err error
		slackClient, err = outputs.NewClient("Slack", config.Slack.WebhookURL, config.Slack.MutualTLS, config.Slack.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Slack.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Slack")
		}
	}

	if config.Cliq.WebhookURL != "" {
		var err error
		cliqClient, err = outputs.NewClient("Cliq", config.Cliq.WebhookURL, config.Cliq.MutualTLS, config.Cliq.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Cliq.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Cliq")
		}
	}

	if config.Rocketchat.WebhookURL != "" {
		var err error
		rocketchatClient, err = outputs.NewClient("Rocketchat", config.Rocketchat.WebhookURL, config.Rocketchat.MutualTLS, config.Rocketchat.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Rocketchat.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Rocketchat")
		}
	}

	if config.Mattermost.WebhookURL != "" {
		var err error
		mattermostClient, err = outputs.NewClient("Mattermost", config.Mattermost.WebhookURL, config.Mattermost.MutualTLS, config.Mattermost.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Mattermost.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Mattermost")
		}
	}

	if config.Teams.WebhookURL != "" {
		var err error
		teamsClient, err = outputs.NewClient("Teams", config.Teams.WebhookURL, config.Teams.MutualTLS, config.Teams.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Teams.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Teams")
		}
	}

	if config.Datadog.APIKey != "" {
		var err error
		datadogClient, err = outputs.NewClient("Datadog", config.Datadog.Host+outputs.DatadogPath+"?api_key="+config.Datadog.APIKey, config.Datadog.MutualTLS, config.Datadog.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Datadog.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Datadog")
		}
	}

	if config.Discord.WebhookURL != "" {
		var err error
		discordClient, err = outputs.NewClient("Discord", config.Discord.WebhookURL, config.Discord.MutualTLS, config.Discord.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Discord.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Discord")
		}
	}

	if config.Alertmanager.HostPort != "" {
		var err error
		alertmanagerClient, err = outputs.NewClient("AlertManager", config.Alertmanager.HostPort+config.Alertmanager.Endpoint, config.Alertmanager.MutualTLS, config.Alertmanager.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Alertmanager.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AlertManager")
		}
	}

	if config.Elasticsearch.HostPort != "" {
		var err error
		elasticsearchClient, err = outputs.NewClient("Elasticsearch", config.Elasticsearch.HostPort+"/"+config.Elasticsearch.Index+"/"+config.Elasticsearch.Type, config.Elasticsearch.MutualTLS, config.Elasticsearch.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Elasticsearch.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Elasticsearch")
		}
	}

	if config.Loki.HostPort != "" {
		var err error
		lokiClient, err = outputs.NewClient("Loki", config.Loki.HostPort+config.Loki.Endpoint, config.Loki.MutualTLS, config.Loki.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Loki.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Loki")
		}
	}

	if config.Nats.HostPort != "" {
		var err error
		natsClient, err = outputs.NewClient("NATS", config.Nats.HostPort, config.Nats.MutualTLS, config.Nats.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Nats.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "NATS")
		}
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" {
		var err error
		stanClient, err = outputs.NewClient("STAN", config.Stan.HostPort, config.Stan.MutualTLS, config.Stan.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Stan.HostPort = ""
			config.Stan.ClusterID = ""
			config.Stan.ClientID = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "STAN")
		}
	}

	if config.Influxdb.HostPort != "" {
		var url string = config.Influxdb.HostPort
		if config.Influxdb.Organization != "" && config.Influxdb.Bucket != "" {
			url += "/api/v2/write?org=" + config.Influxdb.Organization + "&bucket=" + config.Influxdb.Bucket
		} else if config.Influxdb.Database != "" {
			url += "/write?db=" + config.Influxdb.Database
		}
		if config.Influxdb.User != "" && config.Influxdb.Password != "" && config.Influxdb.Token == "" {
			url += "&u=" + config.Influxdb.User + "&p=" + config.Influxdb.Password
		}
		if config.Influxdb.Precision != "" {
			url += "&precision=" + config.Influxdb.Precision
		}

		var err error
		influxdbClient, err = outputs.NewClient("Influxdb", url, config.Influxdb.MutualTLS, config.Influxdb.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Influxdb.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Influxdb")
		}
	}

	if config.AWS.Lambda.FunctionName != "" || config.AWS.SQS.URL != "" ||
		config.AWS.SNS.TopicArn != "" || config.AWS.CloudWatchLogs.LogGroup != "" || config.AWS.S3.Bucket != "" ||
		config.AWS.Kinesis.StreamName != "" || (config.AWS.SecurityLake.Bucket != "" && config.AWS.SecurityLake.Region != "" && config.AWS.SecurityLake.AccountID != "") {
		var err error
		awsClient, err = outputs.NewAWSClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.AWS.AccessKeyID = ""
			config.AWS.SecretAccessKey = ""
			config.AWS.Region = ""
			config.AWS.Lambda.FunctionName = ""
			config.AWS.SQS.URL = ""
			config.AWS.S3.Bucket = ""
			config.AWS.SNS.TopicArn = ""
			config.AWS.CloudWatchLogs.LogGroup = ""
			config.AWS.CloudWatchLogs.LogStream = ""
			config.AWS.Kinesis.StreamName = ""
			config.AWS.SecurityLake.Region = ""
			config.AWS.SecurityLake.Bucket = ""
			config.AWS.SecurityLake.AccountID = ""
		} else {
			if config.AWS.Lambda.FunctionName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSLambda")
			}
			if config.AWS.SQS.URL != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSSQS")
			}
			if config.AWS.SNS.TopicArn != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSSNS")
			}
			if config.AWS.CloudWatchLogs.LogGroup != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSCloudWatchLogs")
			}
			if config.AWS.S3.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSS3")
			}
			if config.AWS.Kinesis.StreamName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSKinesis")
			}
			if config.AWS.SecurityLake.Bucket != "" && config.AWS.SecurityLake.Region != "" && config.AWS.SecurityLake.AccountID != "" && config.AWS.SecurityLake.Prefix != "" {
				config.AWS.SecurityLake.Ctx = context.Background()
				config.AWS.SecurityLake.ReadOffset, config.AWS.SecurityLake.WriteOffset = new(memlog.Offset), new(memlog.Offset)
				config.AWS.SecurityLake.Memlog, err = memlog.New(config.AWS.SecurityLake.Ctx, memlog.WithMaxSegmentSize(10000))
				if config.AWS.SecurityLake.Interval < 5 {
					config.AWS.SecurityLake.Interval = 5
				}
				go awsClient.StartSecurityLakeWorker()
				if err != nil {
					config.AWS.SecurityLake.Region = ""
					config.AWS.SecurityLake.Bucket = ""
					config.AWS.SecurityLake.AccountID = ""
					config.AWS.SecurityLake.Prefix = ""
				} else {
					outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSSecurityLake")
				}
			}
		}
	}

	if config.SMTP.HostPort != "" && config.SMTP.From != "" && config.SMTP.To != "" {
		var err error
		smtpClient, err = outputs.NewSMTPClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.SMTP.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "SMTP")
		}
	}

	if config.Opsgenie.APIKey != "" {
		var err error
		url := "https://api.opsgenie.com/v2/alerts"
		if strings.ToLower(config.Opsgenie.Region) == "eu" {
			url = "https://api.eu.opsgenie.com/v2/alerts"
		}
		opsgenieClient, err = outputs.NewClient("Opsgenie", url, config.Opsgenie.MutualTLS, config.Opsgenie.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Opsgenie.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Opsgenie")
		}
	}

	if config.Webhook.Address != "" {
		var err error
		webhookClient, err = outputs.NewClient("Webhook", config.Webhook.Address, config.Webhook.MutualTLS, config.Webhook.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Webhook.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Webhook")
		}
	}

	if config.NodeRed.Address != "" {
		var err error
		noderedClient, err = outputs.NewClient("NodeRed", config.NodeRed.Address, false, config.NodeRed.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.NodeRed.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "NodeRed")
		}
	}

	if config.CloudEvents.Address != "" {
		var err error
		cloudeventsClient, err = outputs.NewClient("CloudEvents", config.CloudEvents.Address, config.CloudEvents.MutualTLS, config.CloudEvents.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.CloudEvents.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "CloudEvents")
		}
	}

	if config.Azure.EventHub.Name != "" {
		var err error
		azureClient, err = outputs.NewEventHubClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Azure.EventHub.Name = ""
			config.Azure.EventHub.Namespace = ""
		} else {
			if config.Azure.EventHub.Name != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "EventHub")
			}
		}
	}

	if (config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "") || config.GCP.Storage.Bucket != "" || config.GCP.CloudFunctions.Name != "" {
		var err error
		gcpClient, err = outputs.NewGCPClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.GCP.PubSub.ProjectID = ""
			config.GCP.PubSub.Topic = ""
			config.GCP.Storage.Bucket = ""
			config.GCP.CloudFunctions.Name = ""
		} else {
			if config.GCP.PubSub.Topic != "" && config.GCP.PubSub.ProjectID != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPPubSub")
			}
			if config.GCP.Storage.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPStorage")
			}
			if config.GCP.CloudFunctions.Name != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPCloudFunctions")
			}
		}
	}

	if config.GCP.CloudRun.Endpoint != "" && config.GCP.CloudRun.JWT != "" {
		var err error
		var outputName = "GCPCloudRun"

		gcpCloudRunClient, err = outputs.NewClient(outputName, config.GCP.CloudRun.Endpoint, false, false, config, stats, promStats, statsdClient, dogstatsdClient, logging)

		if err != nil {
			config.GCP.CloudRun.Endpoint = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
		}
	}

	if config.Googlechat.WebhookURL != "" {
		var err error
		googleChatClient, err = outputs.NewClient("Googlechat", config.Googlechat.WebhookURL, config.Googlechat.MutualTLS, config.Googlechat.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Googlechat.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GoogleChat")
		}
	}

	if config.Kafka.HostPort != "" && config.Kafka.Topic != "" {
		var err error
		kafkaClient, err = outputs.NewKafkaClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Kafka.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Kafka")
		}
	}

	if config.KafkaRest.Address != "" {
		var err error
		kafkaRestClient, err = outputs.NewClient("KafkaRest", config.KafkaRest.Address, config.KafkaRest.MutualTLS, config.KafkaRest.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.KafkaRest.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "KafkaRest")
		}
	}

	if config.Pagerduty.RoutingKey != "" {
		var err error
		var url = "https://events.pagerduty.com/v2/enqueue"
		var outputName = "Pagerduty"

		pagerdutyClient, err = outputs.NewClient(outputName, url, config.Pagerduty.MutualTLS, config.Pagerduty.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)

		if err != nil {
			config.Pagerduty.RoutingKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
		}
	}

	if config.Kubeless.Namespace != "" && config.Kubeless.Function != "" {
		var err error
		kubelessClient, err = outputs.NewKubelessClient(config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			logging.Error().Err(err).Msg("Kubeless")
			config.Kubeless.Namespace = ""
			config.Kubeless.Function = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Kubeless")
		}
	}

	if config.WebUI.URL != "" {
		var err error
		webUIClient, err = outputs.NewClient("WebUI", config.WebUI.URL, config.WebUI.MutualTLS, config.WebUI.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.WebUI.URL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "WebUI")
		}
	}

	if config.PolicyReport.Enabled {
		var err error
		policyReportClient, err = outputs.NewPolicyReportClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.PolicyReport.Enabled = false
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "PolicyReport")
		}
	}

	if config.Openfaas.FunctionName != "" {
		var err error
		openfaasClient, err = outputs.NewOpenfaasClient(config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			logging.Error().Err(err).Msg("OpenFaaS")
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "OpenFaaS")
		}
	}

	if config.Tekton.EventListener != "" {
		var err error
		tektonClient, err = outputs.NewClient("Tekton", config.Tekton.EventListener, false, config.Tekton.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			logging.Error().Err(err).Msg("Tekton")
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Tekton")
		}
	}

	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" {
		var err error
		rabbitmqClient, err = outputs.NewRabbitmqClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Rabbitmq.URL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "RabbitMQ")
		}
	}

	if config.Wavefront.EndpointType != "" && config.Wavefront.EndpointHost != "" {
		var err error
		wavefrontClient, err = outputs.NewWavefrontClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			logging.Error().Err(err).Msg("Wavefront")
			config.Wavefront.EndpointHost = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Wavefront")
		}
	}

	if config.Fission.Function != "" {
		var err error
		fissionClient, err = outputs.NewFissionClient(config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			logging.Error().Err(err).Msg("Fission")
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputs.Fission)
		}
	}

	if config.Grafana.HostPort != "" && config.Grafana.APIKey != "" {
		var err error
		var outputName = "Grafana"
		grafanaClient, err = outputs.NewClient(outputName, config.Grafana.HostPort+"/api/annotations", config.Grafana.MutualTLS, config.Grafana.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Grafana.HostPort = ""
			config.Grafana.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
		}
	}

	if config.GrafanaOnCall.WebhookURL != "" {
		var err error
		var outputName = "GrafanaOnCall"
		grafanaOnCallClient, err = outputs.NewClient(outputName, config.GrafanaOnCall.WebhookURL, config.GrafanaOnCall.MutualTLS, config.GrafanaOnCall.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.GrafanaOnCall.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
		}
	}

	if config.Yandex.S3.Bucket != "" {
		var err error
		yandexClient, err = outputs.NewYandexClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Yandex.S3.Bucket = ""
			logging.Error().Err(err).Msg("Yandex")
		} else {
			if config.Yandex.S3.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "YandexS3")
			}
		}
	}

	if config.Yandex.DataStreams.StreamName != "" {
		var err error
		yandexClient, err = outputs.NewYandexClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Yandex.DataStreams.StreamName = ""
			logging.Error().Err(err).Msg("Yandex")
		} else {
			if config.Yandex.DataStreams.StreamName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "YandexDataStreams")
			}
		}
	}

	if config.Syslog.Host != "" {
		var err error
		syslogClient, err = outputs.NewSyslogClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Syslog.Host = ""
			logging.Error().Err(err).Msg("Syslog")
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Syslog")
		}
	}

	if config.MQTT.Broker != "" {
		var err error
		mqttClient, err = outputs.NewMQTTClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.MQTT.Broker = ""
			logging.Error().Err(err).Msg("MQTT")
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "MQTT")
		}
	}

	if config.Zincsearch.HostPort != "" {
		var err error
		zincsearchClient, err = outputs.NewClient("Zincsearch", config.Zincsearch.HostPort+"/api/"+config.Zincsearch.Index+"/_doc", false, config.Zincsearch.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Zincsearch.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Zincsearch")
		}
	}

	if config.Gotify.HostPort != "" {
		var err error
		gotifyClient, err = outputs.NewClient("Gotify", config.Gotify.HostPort+"/message", false, config.Gotify.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.Gotify.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Gotify")
		}
	}

	if config.Spyderbat.OrgUID != "" {
		var err error
		spyderbatClient, err = outputs.NewSpyderbatClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Spyderbat.OrgUID = ""
			logging.Error().Err(err).Msg("Spyderbat")
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Spyderbat")
		}
	}

	if config.TimescaleDB.Host != "" {
		var err error
		timescaleDBClient, err = outputs.NewTimescaleDBClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.TimescaleDB.Host = ""
			logging.Error().Err(err).Msg("TimescaleDB")
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "TimescaleDB")
		}
	}

	if config.Redis.Address != "" {
		var err error
		redisClient, err = outputs.NewRedisClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Redis.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Redis")
		}
	}

	if config.Telegram.ChatID != "" && config.Telegram.Token != "" {
		var err error
		var urlFormat = "https://api.telegram.org/bot%s/sendMessage"

		telegramClient, err = outputs.NewClient("Telegram", fmt.Sprintf(urlFormat, config.Telegram.Token), false, config.Telegram.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)

		if err != nil {
			config.Telegram.ChatID = ""
			config.Telegram.Token = ""

			logging.Error().Err(err).Msg("Telegram")
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Telegram")
		}
	}

	if config.N8N.Address != "" {
		var err error
		n8nClient, err = outputs.NewClient("n8n", config.N8N.Address, false, config.N8N.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient, logging)
		if err != nil {
			config.N8N.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "n8n")
		}
	}

	if config.OpenObserve.HostPort != "" {
		var err error
		openObserveClient, err = outputs.NewClient("OpenObserve", config.OpenObserve.HostPort+"/api/"+config.OpenObserve.OrganizationName+"/"+config.OpenObserve.StreamName+"/_multi", config.OpenObserve.MutualTLS, config.OpenObserve.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.OpenObserve.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "OpenObserve")
		}
	}

	logging.Info().Str("version", GetVersionInfo().GitVersion).Msg("Falco Sidekick")
	logging.Info().Msgf("Enabled Outputs : %s", outputs.EnabledOutputs)

}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/healthz", healthHandler)
	http.HandleFunc("/test", testHandler)
	http.Handle("/metrics", promhttp.Handler())

	logging.Info().Str("address", config.ListenAddress).Str("port", fmt.Sprint(config.ListenPort)).Msgf("Falco Sidekick is up!")
	if config.Debug {
		logging.Info().Str("debug", strconv.FormatBool(config.Debug)).Msg("")
	}

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort),
		// Timeouts
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if config.TLSServer.Deploy {
		if config.TLSServer.MutualTLS {
			if config.Debug {
				log.Printf("[DEBUG] : running mTLS server")
			}

			caCert, err := ioutil.ReadFile(config.TLSServer.CaCertFile)
			if err != nil {
				log.Printf("[ERROR] : %v\n", err.Error())
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)

			server.TLSConfig = &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			}
		}

		if config.Debug && !config.TLSServer.MutualTLS {
			log.Printf("[DEBUG] : running TLS server")
		}

		if err := server.ListenAndServeTLS(config.TLSServer.CertFile, config.TLSServer.KeyFile); err != nil {
			log.Fatalf("[ERROR] : %v", err.Error())
		}
	} else {
		if config.Debug {
			log.Printf("[DEBUG] : running HTTP server")
		}

		if config.TLSServer.MutualTLS {
			log.Printf("[WARN] : tlsserver.deploy is false but tlsserver.mutualtls is true, change tlsserver.deploy to true to use mTLS")
		}
		if err := server.ListenAndServe(); err != nil {
			logging.Fatal().Err(err).Msgf("Error while starting Falco Sidekick")
		}
}
