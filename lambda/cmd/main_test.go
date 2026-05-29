package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// ── Mock handlers ─────────────────────────────────────────────────────────────

type mockHandler struct{ mock.Mock }

func (m *mockHandler) Handle(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	args := m.Called(ctx, event)
	return args.Get(0).(events.APIGatewayV2HTTPResponse), args.Error(1)
}

// ── Mock Secrets Manager ──────────────────────────────────────────────────────

type mockSM struct{ mock.Mock }

func (m *mockSM) GetSecretValue(ctx context.Context, p *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	args := m.Called(ctx, p)
	out, _ := args.Get(0).(*secretsmanager.GetSecretValueOutput)
	return out, args.Error(1)
}

// ── dispatch ──────────────────────────────────────────────────────────────────

func makeEvent(method, path string) events.APIGatewayV2HTTPRequest {
	return events.APIGatewayV2HTTPRequest{
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: method, Path: path},
		},
	}
}

func withMockHandlers(vote, results eventHandler, fn func()) {
	origVote, origResults := voteHandler, resultsHandler
	defer func() { voteHandler, resultsHandler = origVote, origResults }()
	voteHandler, resultsHandler = vote, results
	fn()
}

func TestDispatch_PostVote(t *testing.T) {
	vote := &mockHandler{}
	vote.On("Handle", mock.Anything, mock.Anything).Return(events.APIGatewayV2HTTPResponse{StatusCode: 200}, nil)

	withMockHandlers(vote, &mockHandler{}, func() {
		resp, err := dispatch(context.Background(), makeEvent(http.MethodPost, "/vote"))
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
	vote.AssertExpectations(t)
}

func TestDispatch_GetResults(t *testing.T) {
	results := &mockHandler{}
	results.On("Handle", mock.Anything, mock.Anything).Return(events.APIGatewayV2HTTPResponse{StatusCode: 200}, nil)

	withMockHandlers(&mockHandler{}, results, func() {
		resp, err := dispatch(context.Background(), makeEvent(http.MethodGet, "/results"))
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
	results.AssertExpectations(t)
}

func TestDispatch_NotFound(t *testing.T) {
	withMockHandlers(&mockHandler{}, &mockHandler{}, func() {
		resp, err := dispatch(context.Background(), makeEvent(http.MethodGet, "/unknown"))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		var body map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(resp.Body), &body))
		assert.Equal(t, "NOT_FOUND", body["error"].(map[string]interface{})["code"])
	})
}

func TestDispatch_PanicReturns500(t *testing.T) {
	panicker := &mockHandler{}
	panicker.On("Handle", mock.Anything, mock.Anything).Panic("unexpected")

	withMockHandlers(panicker, &mockHandler{}, func() {
		resp, err := dispatch(context.Background(), makeEvent(http.MethodPost, "/vote"))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		var body map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(resp.Body), &body))
		assert.Equal(t, "INTERNAL_ERROR", body["error"].(map[string]interface{})["code"])
	})
}

// ── fetchSalt ─────────────────────────────────────────────────────────────────

func TestFetchSalt_EmptyName_DevFallback(t *testing.T) {
	salt, err := fetchSalt(context.Background(), &mockSM{}, "")
	assert.NoError(t, err)
	assert.Equal(t, []byte("dev-fallback-salt-not-for-production"), salt)
}

func TestFetchSalt_GetSecretValueError(t *testing.T) {
	sm := &mockSM{}
	sm.On("GetSecretValue", mock.Anything, mock.Anything).Return(nil, errors.New("access denied"))

	_, err := fetchSalt(context.Background(), sm, "my-secret")
	assert.ErrorContains(t, err, "access denied")
}

func TestFetchSalt_NilSecretString(t *testing.T) {
	sm := &mockSM{}
	sm.On("GetSecretValue", mock.Anything, mock.Anything).Return(&secretsmanager.GetSecretValueOutput{SecretString: nil}, nil)

	_, err := fetchSalt(context.Background(), sm, "my-secret")
	assert.ErrorContains(t, err, "no string value")
}

func TestFetchSalt_InvalidJSON(t *testing.T) {
	sm := &mockSM{}
	bad := "not-json"
	sm.On("GetSecretValue", mock.Anything, mock.Anything).Return(&secretsmanager.GetSecretValueOutput{SecretString: &bad}, nil)

	_, err := fetchSalt(context.Background(), sm, "my-secret")
	assert.ErrorContains(t, err, "unmarshal salt JSON")
}

func TestFetchSalt_InvalidBase64(t *testing.T) {
	sm := &mockSM{}
	payload := `{"salt":"not-valid-base64!!!"}`
	sm.On("GetSecretValue", mock.Anything, mock.Anything).Return(&secretsmanager.GetSecretValueOutput{SecretString: &payload}, nil)

	_, err := fetchSalt(context.Background(), sm, "my-secret")
	assert.ErrorContains(t, err, "base64-decode salt")
}

func TestFetchSalt_Valid(t *testing.T) {
	rawSalt := make([]byte, 32)
	for i := range rawSalt {
		rawSalt[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(rawSalt)
	payload, _ := json.Marshal(map[string]string{"salt": encoded})
	payloadStr := string(payload)

	sm := &mockSM{}
	sm.On("GetSecretValue", mock.Anything, mock.Anything).Return(&secretsmanager.GetSecretValueOutput{SecretString: &payloadStr}, nil)

	salt, err := fetchSalt(context.Background(), sm, "my-secret")
	assert.NoError(t, err)
	assert.Equal(t, rawSalt, salt)
}
