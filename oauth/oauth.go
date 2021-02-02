package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/sshindanai/bookstore-utils-go/resterrors"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:1323",
		Timeout: 100 * time.Millisecond,
	}
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-ClientId"
	headerXCallerID = "X-CallerId"

	paramUserID = "userid"
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

func ClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

func CallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func AuthenticateRequest(request *http.Request) resterrors.RestErr {
	if request == nil {
		return nil
	}

	userID := strings.TrimSpace(request.URL.Query().Get(paramUserID))
	if userID == "" {
		return nil
	}

	at, err := getAccessToken(userID)
	if err != nil {
		if err.StatusCode() == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func getAccessToken(userID string) (*accessToken, resterrors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/accesstoken/%s", userID))
	if response == nil || response.Response == nil {
		return nil, resterrors.NewNotFoundError("invalid restclient response when trying to get access token")
	}

	if response.StatusCode > 299 {
		var restErr resterrors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, resterrors.NewNotFoundError("invalid error interface when trying to get access token")
		}
		return nil, restErr
	}

	var token accessToken
	if err := json.Unmarshal(response.Bytes(), &token); err != nil {
		return nil, resterrors.NewNotFoundError("error when trying to unmarshal access token")
	}
	return &token, nil
}
