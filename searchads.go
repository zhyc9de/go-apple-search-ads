package go_apple_search_ads

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-querystring/query"
	jsoniter "github.com/json-iterator/go"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

var json = jsoniter.ConfigFastest

const (
	defaultBaseURL = "https://api.searchads.apple.com/api/v4/"
)

// A Client manages communication with the Google Search Ads API.
type Client struct {
	baseURL           *url.URL
	token             *jwt.Token
	privateKey        *ecdsa.PrivateKey
	clientID          string
	teamID            string
	orgID             string
	accessToken       string
	accessTokenExpire int64

	Campaign                *CampaignService
	AdGroup                 *AdGroupService
	ACL                     *ACLService
	CampaignNegativeKeyword *CampaignNegativeKeywordService
	AdGroupNegativeKeyword  *AdGroupNegativeKeywordService
	AdGroupTargetingKeyword *AdGroupTargetingKeywordService
	Report                  *ReportService
}

type service struct {
	client *Client
}

// ListOptions to hold url params like pagination
type ListOptions struct {
	Limit  int `url:"limit,omitempty"`
	Offset int `url:"offset,omitempty"`
}

// addOptions adds the parameters in opt as URL query parameters to s. opt
// must be a struct whose fields may contain "url" tags.
func addOptions(s string, opt interface{}) (string, error) {
	v := reflect.ValueOf(opt)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return s, nil
	}

	u, err := url.Parse(s)
	if err != nil {
		return s, err
	}

	qs, err := query.Values(opt)
	if err != nil {
		return s, err
	}

	u.RawQuery = qs.Encode()
	return u.String(), nil
}

func NewClient(orgID, clientID, teamID, keyID string, privateKey []byte) *Client {
	baseURL, _ := url.Parse(defaultBaseURL)
	c := &Client{baseURL: baseURL}

	c.privateKey, _ = jwt.ParseECPrivateKeyFromPEM(privateKey)
	c.clientID = clientID
	c.teamID = teamID
	c.orgID = orgID
	c.token = jwt.New(jwt.SigningMethodES256)
	c.token.Header["kid"] = keyID

	common := service{c}
	c.Campaign = (*CampaignService)(&common)
	c.CampaignNegativeKeyword = (*CampaignNegativeKeywordService)(&common)
	c.AdGroup = (*AdGroupService)(&common)
	c.AdGroupNegativeKeyword = (*AdGroupNegativeKeywordService)(&common)
	c.AdGroupTargetingKeyword = (*AdGroupTargetingKeywordService)(&common)
	c.ACL = (*ACLService)(&common)
	c.Report = (*ReportService)(&common)

	return c
}

func (c *Client) setToken(req *http.Request) {
	now := time.Now().Unix()
	if now > c.accessTokenExpire {
		c.token.Claims = jwt.MapClaims{
			"sub": c.clientID,
			"aud": "https://appleid.apple.com",
			"iss": c.teamID,
			"iat": now,
			"exp": now + 3600 - 100,
		}
		secret, _ := c.token.SignedString(c.privateKey)
		param := url.Values{}
		param.Set("client_id", c.clientID)
		param.Set("client_secret", secret)
		param.Set("grant_type", "client_credentials")
		param.Set("scope", "searchadsorg")
		req2, _ := http.NewRequest(http.MethodPost, "https://appleid.apple.com/auth/oauth2/token?"+param.Encode(), nil)
		resp, err := http.DefaultClient.Do(req2)
		if err != nil {
			fmt.Println("request access_token failed", err)
			return
		}
		defer resp.Body.Close()

		respBody, _ := ioutil.ReadAll(resp.Body)
		c.accessToken = jsoniter.Get(respBody, "access_token").ToString()
		c.accessTokenExpire = now + jsoniter.Get(respBody, "expires_in").ToInt64() - 100
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("X-AP-Context", "orgId="+c.orgID)
}

// NewRequest to build request
func (c *Client) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	if !strings.HasSuffix(c.baseURL.Path, "/") {
		return nil, fmt.Errorf("baseURL must have a trailing slash, but %q does not", c.baseURL)
	}
	u, err := c.baseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		err = enc.Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, _ := http.NewRequest(method, u.String(), buf)
	c.setToken(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// Do to execute request and handle response of all services
func (c *Client) Do(ctx context.Context, req *http.Request, v interface{}) (*Response, error) {
	req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	response := newResponse(resp)
	err = CheckResponse(resp)
	if err != nil {
		return response, err
	}
	type Response struct {
		Data       interface{}
		Pagination Pagination
	}
	rv := &Response{Data: v}
	err = json.NewDecoder(resp.Body).Decode(rv)
	response.Pagination = rv.Pagination
	return response, err
}

// Response to hold apple serach ads response with page details
type Response struct {
	*http.Response
	Pagination
}

// Pagination Struct to hold pagination information
type Pagination struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
}

// newResponse creates a new Response for the provided http.Response.
// r must not be nil.
func newResponse(r *http.Response) *Response {
	response := &Response{Response: r}
	return response
}

// CheckResponse to build an erro if code is not 2xx
func CheckResponse(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	errorResponse := &ErrorResponse{Response: r}
	data, err := ioutil.ReadAll(r.Body)
	if err == nil && data != nil {
		json.Unmarshal(data, errorResponse)
	}
	return errorResponse
}

/*
An ErrorResponse reports one or more errors caused by an API request.
*/
type ErrorResponse struct {
	Response *http.Response // HTTP response that caused this error
	Errors   Errors         `json:"error"` // more detail on individual errors
}

// Errors struct holds all messages
type Errors struct {
	Messages []ErrorMessage `json:"errors"`
}

// ErrorMessage with details
type ErrorMessage struct {
	MessageCode string `json:"messageCode"`
	Message     string `json:"message"`
	Field       string `json:"field"`
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("%v %v: %d %+v",
		r.Response.Request.Method, r.Response.Request.URL,
		r.Response.StatusCode, r.Errors)
}
