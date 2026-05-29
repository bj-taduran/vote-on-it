package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/bj-taduran/vote-on-it/internal/handler"
	"github.com/bj-taduran/vote-on-it/internal/model"
	"github.com/bj-taduran/vote-on-it/internal/repository"
)

// ── Mock service ──────────────────────────────────────────────────────────────

type mockPollService struct{ mock.Mock }

func (m *mockPollService) CastVote(ctx context.Context, req *model.VoteRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockPollService) GetResults(ctx context.Context, pollID string) (*model.ResultsResponse, error) {
	args := m.Called(ctx, pollID)
	res, _ := args.Get(0).(*model.ResultsResponse)
	return res, args.Error(1)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func voteEvent(body string) events.APIGatewayV2HTTPRequest {
	return events.APIGatewayV2HTTPRequest{
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method: http.MethodPost,
				Path:   "/vote",
			},
		},
		Headers: map[string]string{"content-type": "application/json"},
		Body:    body,
	}
}

func voteEventWithContentType(body, contentType string) events.APIGatewayV2HTTPRequest {
	e := voteEvent(body)
	e.Headers = map[string]string{"content-type": contentType}
	return e
}

func voteEventNoContentType(body string) events.APIGatewayV2HTTPRequest {
	e := voteEvent(body)
	e.Headers = map[string]string{}
	return e
}

func validVoteBody() string {
	b, _ := json.Marshal(map[string]string{
		"poll_id":  "poll-2026-001",
		"option":   "A",
		"voter_id": "550e8400-e29b-41d4-a716-446655440000",
	})
	return string(b)
}

func decodeBody(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(body), &m))
	return m
}

func errorCode(t *testing.T, body string) string {
	t.Helper()
	return decodeBody(t, body)["error"].(map[string]interface{})["code"].(string)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestVoteHandler_Success(t *testing.T) {
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(nil)

	h := handler.NewVote(svc)
	resp, err := h.Handle(context.Background(), voteEvent(validVoteBody()))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp.Body)
	assert.Equal(t, "ok", body["status"])
	svc.AssertExpectations(t)
}

func TestVoteHandler_BodyTooLarge(t *testing.T) {
	oversized := `{"poll_id":"poll-2026-001","option":"A","voter_id":"550e8400-e29b-41d4-a716-446655440000","pad":"` + strings.Repeat("x", 512) + `"}`
	h := handler.NewVote(&mockPollService{})
	resp, err := h.Handle(context.Background(), voteEvent(oversized))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "REQUEST_TOO_LARGE", errorCode(t, resp.Body))
}

func TestVoteHandler_MissingContentType(t *testing.T) {
	h := handler.NewVote(&mockPollService{})
	resp, err := h.Handle(context.Background(), voteEventNoContentType(validVoteBody()))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "INVALID_CONTENT_TYPE", errorCode(t, resp.Body))
}

func TestVoteHandler_WrongContentType(t *testing.T) {
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", ""} {
		h := handler.NewVote(&mockPollService{})
		resp, err := h.Handle(context.Background(), voteEventWithContentType(validVoteBody(), ct))

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "content-type=%q", ct)
		assert.Equal(t, "INVALID_CONTENT_TYPE", errorCode(t, resp.Body))
	}
}

func TestVoteHandler_ContentTypeWithCharset(t *testing.T) {
	// application/json; charset=utf-8 must be accepted.
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(nil)

	h := handler.NewVote(svc)
	resp, err := h.Handle(context.Background(), voteEventWithContentType(validVoteBody(), "application/json; charset=utf-8"))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestVoteHandler_InvalidJSON(t *testing.T) {
	h := handler.NewVote(&mockPollService{})
	resp, err := h.Handle(context.Background(), voteEvent("not json"))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "INVALID_JSON", errorCode(t, resp.Body))
}

func TestVoteHandler_UnknownFields(t *testing.T) {
	body := `{"poll_id":"poll-001","option":"A","voter_id":"550e8400-e29b-41d4-a716-446655440000","extra":"bad"}`
	h := handler.NewVote(&mockPollService{})
	resp, err := h.Handle(context.Background(), voteEvent(body))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestVoteHandler_MissingFields(t *testing.T) {
	cases := []struct {
		body string
		code string
	}{
		{`{"option":"A","voter_id":"550e8400-e29b-41d4-a716-446655440000"}`, "MISSING_POLL_ID"},
		{`{"poll_id":"poll-001","voter_id":"550e8400-e29b-41d4-a716-446655440000"}`, "MISSING_OPTION"},
		{`{"poll_id":"poll-001","option":"A"}`, "MISSING_VOTER_ID"},
	}
	for _, tc := range cases {
		h := handler.NewVote(&mockPollService{})
		resp, err := h.Handle(context.Background(), voteEvent(tc.body))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", tc.body)
		assert.Equal(t, tc.code, errorCode(t, resp.Body))
	}
}

func TestVoteHandler_InvalidPollID(t *testing.T) {
	// Empty string is covered by TestVoteHandler_MissingFields (returns MISSING_POLL_ID).
	cases := []string{"POLL-001", "poll_001", "a", fmt.Sprintf("poll-%s", string(make([]byte, 55)))}
	for _, id := range cases {
		b, _ := json.Marshal(map[string]string{"poll_id": id, "option": "A", "voter_id": "550e8400-e29b-41d4-a716-446655440000"})
		h := handler.NewVote(&mockPollService{})
		resp, _ := h.Handle(context.Background(), voteEvent(string(b)))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "poll_id=%q", id)
		assert.Equal(t, "INVALID_POLL_ID", errorCode(t, resp.Body))
	}
}

func TestVoteHandler_InvalidOption(t *testing.T) {
	// Empty string is covered by TestVoteHandler_MissingFields (returns MISSING_OPTION).
	for _, opt := range []string{"E", "a", "AB"} {
		b, _ := json.Marshal(map[string]string{"poll_id": "poll-001", "option": opt, "voter_id": "550e8400-e29b-41d4-a716-446655440000"})
		h := handler.NewVote(&mockPollService{})
		resp, _ := h.Handle(context.Background(), voteEvent(string(b)))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "option=%q", opt)
		assert.Equal(t, "INVALID_OPTION", errorCode(t, resp.Body))
	}
}

func TestVoteHandler_InvalidVoterID(t *testing.T) {
	// Empty string is covered by TestVoteHandler_MissingFields (returns MISSING_VOTER_ID).
	cases := []string{
		"not-a-uuid",
		"550E8400-E29B-41D4-A716-446655440000", // uppercase — rejected
		"550e8400-e29b-11d4-a716-446655440000", // version nibble is 1, not 4
		"550e8400-e29b-41d4-c716-446655440000", // variant nibble is c, not in [89ab]
	}
	for _, id := range cases {
		b, _ := json.Marshal(map[string]string{"poll_id": "poll-001", "option": "B", "voter_id": id})
		h := handler.NewVote(&mockPollService{})
		resp, _ := h.Handle(context.Background(), voteEvent(string(b)))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "voter_id=%q", id)
		assert.Equal(t, "INVALID_VOTER_ID", errorCode(t, resp.Body))
	}
}

func TestVoteHandler_DuplicateVote(t *testing.T) {
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(repository.ErrDuplicateVote)

	h := handler.NewVote(svc)
	resp, err := h.Handle(context.Background(), voteEvent(validVoteBody()))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "VOTE_ALREADY_CAST", errorCode(t, resp.Body))
}

func TestVoteHandler_WrappedDuplicateVote(t *testing.T) {
	// errors.Is must unwrap the duplicate sentinel even when wrapped.
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(fmt.Errorf("outer: %w", repository.ErrDuplicateVote))

	h := handler.NewVote(svc)
	resp, _ := h.Handle(context.Background(), voteEvent(validVoteBody()))

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestVoteHandler_ServiceError(t *testing.T) {
	svc := &mockPollService{}
	svc.On("CastVote", mock.Anything, mock.Anything).Return(errors.New("unexpected db error"))

	h := handler.NewVote(svc)
	resp, err := h.Handle(context.Background(), voteEvent(validVoteBody()))

	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "INTERNAL_ERROR", errorCode(t, resp.Body))
}

func TestVoteHandler_AllValidOptions(t *testing.T) {
	for _, opt := range []string{"A", "B", "C", "D"} {
		svc := &mockPollService{}
		svc.On("CastVote", mock.Anything, mock.Anything).Return(nil)

		b, _ := json.Marshal(map[string]string{"poll_id": "poll-001", "option": opt, "voter_id": "550e8400-e29b-41d4-a716-446655440000"})
		h := handler.NewVote(svc)
		resp, _ := h.Handle(context.Background(), voteEvent(string(b)))

		assert.Equal(t, http.StatusOK, resp.StatusCode, "option=%s", opt)
	}
}
