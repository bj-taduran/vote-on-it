package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/bj-taduran/vote-on-it/internal/audit"
	"github.com/bj-taduran/vote-on-it/internal/handler"
	"github.com/bj-taduran/vote-on-it/internal/model"
	"github.com/bj-taduran/vote-on-it/internal/repository"
	"github.com/bj-taduran/vote-on-it/internal/service"
)

// eventHandler is the routing interface for the two Lambda endpoints.
// Using an interface here lets tests substitute mocks without AWS clients.
type eventHandler interface {
	Handle(context.Context, events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error)
}

// secretsManagerAPI is the Secrets Manager capability used by fetchSalt.
type secretsManagerAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

var (
	voteHandler    eventHandler
	resultsHandler eventHandler
)

// init runs once at Lambda cold-start. Failures here abort the instance.
func init() {
	ctx := context.Background()

	region := os.Getenv("AWS_REGION_NAME")
	if region == "" {
		region = "eu-central-1"
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		log.Fatalf(`{"level":"FATAL","message":"aws_config_load_failed","error":%q}`, err.Error())
	}

	dynamo := dynamodb.NewFromConfig(cfg)
	sm := secretsmanager.NewFromConfig(cfg)

	repo := repository.New(
		dynamo,
		os.Getenv("POLL_RESULTS_TABLE"),
		os.Getenv("VOTER_LOG_TABLE"),
		os.Getenv("AUDIT_LOG_TABLE"),
	)

	auditor := audit.New(repo)

	salt, err := fetchSalt(ctx, sm, os.Getenv("HMAC_SALT_SECRET_NAME"))
	if err != nil {
		log.Fatalf(`{"level":"FATAL","message":"hmac_salt_fetch_failed","error":%q}`, err.Error())
	}

	ttlHours, _ := strconv.ParseInt(os.Getenv("VOTER_DEDUP_TTL_HOURS"), 10, 64)
	if ttlHours <= 0 {
		ttlHours = 24
	}

	svc := service.New(repo, auditor, salt, ttlHours)
	voteHandler = handler.NewVote(svc)
	resultsHandler = handler.NewResults(svc)
}

func main() {
	lambda.Start(dispatch)
}

// dispatch routes the incoming event to the correct handler.
// A deferred recover catches any unexpected panics and returns a sanitised 500.
func dispatch(ctx context.Context, event events.APIGatewayV2HTTPRequest) (resp events.APIGatewayV2HTTPResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf(`{"level":"ERROR","message":"panic_recovered"}`)
			resp = panicResponse()
			err = nil
		}
	}()

	method := event.RequestContext.HTTP.Method
	path := event.RequestContext.HTTP.Path

	switch {
	case method == http.MethodPost && path == "/vote":
		return voteHandler.Handle(ctx, event)
	case method == http.MethodGet && path == "/results":
		return resultsHandler.Handle(ctx, event)
	default:
		return notFoundResponse(), nil
	}
}

// saltSecret matches the JSON structure stored in Secrets Manager: {"salt":"<base64>"}.
type saltSecret struct {
	Salt string `json:"salt"`
}

// fetchSalt retrieves the HMAC key from Secrets Manager and decodes it from base64.
// If secretName is empty (local dev without AWS), a fixed dev fallback is returned
// with a warning — this must never reach production.
func fetchSalt(ctx context.Context, client secretsManagerAPI, secretName string) ([]byte, error) {
	if secretName == "" {
		log.Printf(`{"level":"WARN","message":"hmac_salt_secret_name_unset_using_dev_fallback"}`)
		return []byte("dev-fallback-salt-not-for-production"), nil
	}

	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return nil, fmt.Errorf("GetSecretValue %q: %w", secretName, err)
	}
	if out.SecretString == nil {
		return nil, fmt.Errorf("secret %q has no string value", secretName)
	}

	var s saltSecret
	if err := json.Unmarshal([]byte(*out.SecretString), &s); err != nil {
		return nil, fmt.Errorf("unmarshal salt JSON: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(s.Salt)
	if err != nil {
		return nil, fmt.Errorf("base64-decode salt: %w", err)
	}
	return raw, nil
}

func notFoundResponse() events.APIGatewayV2HTTPResponse {
	b, _ := json.Marshal(model.ErrorResponse{
		Error: model.ErrorDetail{Code: "NOT_FOUND", Message: "The requested endpoint does not exist."},
	})
	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusNotFound,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(b),
	}
}

func panicResponse() events.APIGatewayV2HTTPResponse {
	b, _ := json.Marshal(model.ErrorResponse{
		Error: model.ErrorDetail{Code: "INTERNAL_ERROR", Message: "An unexpected error occurred."},
	})
	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusInternalServerError,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(b),
	}
}
