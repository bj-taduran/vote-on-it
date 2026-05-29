package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/aws/aws-lambda-go/events"

	"github.com/bj-taduran/vote-on-it/internal/model"
)

// PollService is the service interface consumed by both handlers.
// Using an interface here decouples the handler layer from the concrete service
// and allows tests to substitute a mock without spinning up AWS clients.
type PollService interface {
	CastVote(ctx context.Context, req *model.VoteRequest) error
	GetResults(ctx context.Context, pollID string) (*model.ResultsResponse, error)
}

// pollIDRegex enforces the poll ID format from CLAUDE.md §4.3.
var pollIDRegex = regexp.MustCompile(`^poll-[a-z0-9-]{1,50}$`)

func apiResponse(status int, body interface{}) events.APIGatewayV2HTTPResponse {
	b, _ := json.Marshal(body)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(b),
	}
}

func badRequest(code, message string) events.APIGatewayV2HTTPResponse {
	return apiResponse(http.StatusBadRequest, model.ErrorResponse{
		Error: model.ErrorDetail{Code: code, Message: message},
	})
}

func internalError() events.APIGatewayV2HTTPResponse {
	return apiResponse(http.StatusInternalServerError, model.ErrorResponse{
		Error: model.ErrorDetail{
			Code:    "INTERNAL_ERROR",
			Message: "An unexpected error occurred.",
		},
	})
}
