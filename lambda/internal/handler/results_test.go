package handler_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/bj-taduran/vote-on-it/internal/handler"
	"github.com/bj-taduran/vote-on-it/internal/model"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func resultsEvent(pollID string) events.APIGatewayV2HTTPRequest {
	params := map[string]string{}
	if pollID != "" {
		params["poll_id"] = pollID
	}
	return events.APIGatewayV2HTTPRequest{
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method: http.MethodGet,
				Path:   "/results",
			},
		},
		QueryStringParameters: params,
	}
}

func sampleResults(pollID string) *model.ResultsResponse {
	return &model.ResultsResponse{
		PollID:  pollID,
		Options: map[string]int64{"A": 10, "B": 5, "C": 3, "D": 2},
		Total:   20,
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestResultsHandler_WithPollIDParam(t *testing.T) {
	svc := &mockPollService{}
	svc.On("GetResults", mock.Anything, "poll-2026-001").Return(sampleResults("poll-2026-001"), nil)

	h := handler.NewResults(svc)
	resp, err := h.Handle(context.Background(), resultsEvent("poll-2026-001"))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Body, "poll-2026-001")
	svc.AssertExpectations(t)
}

func TestResultsHandler_DefaultPollID(t *testing.T) {
	// When poll_id query param is absent the handler must use "poll-2026-001".
	svc := &mockPollService{}
	svc.On("GetResults", mock.Anything, "poll-2026-001").Return(sampleResults("poll-2026-001"), nil)

	h := handler.NewResults(svc)
	resp, err := h.Handle(context.Background(), resultsEvent(""))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	svc.AssertExpectations(t)
}

func TestResultsHandler_InvalidPollID(t *testing.T) {
	for _, id := range []string{"POLL-001", "poll_001", "toolong-" + string(make([]byte, 55))} {
		h := handler.NewResults(&mockPollService{})
		resp, err := h.Handle(context.Background(), resultsEvent(id))

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "poll_id=%q", id)
		body := decodeBody(t, resp.Body)
		assert.Equal(t, "INVALID_POLL_ID", body["error"].(map[string]interface{})["code"])
	}
}

func TestResultsHandler_ServiceError(t *testing.T) {
	svc := &mockPollService{}
	svc.On("GetResults", mock.Anything, mock.Anything).Return(nil, errors.New("db down"))

	h := handler.NewResults(svc)
	resp, err := h.Handle(context.Background(), resultsEvent("poll-2026-001"))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	body := decodeBody(t, resp.Body)
	assert.Equal(t, "INTERNAL_ERROR", body["error"].(map[string]interface{})["code"])
}
