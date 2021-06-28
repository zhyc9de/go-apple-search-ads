package go_apple_search_ads

import (
	"context"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"io/ioutil"
	"testing"
)

var (
	orgID    = ""
	clientID = ""
	teamID   = ""
	keyID    = ""
)

func TestNewClient(t *testing.T) {
	privateKey, _ := ioutil.ReadFile("")
	c := NewClient(orgID, clientID, teamID, keyID, privateKey)
	if campaign, _, err := c.Campaign.List(context.Background(), &ListOptions{
		Limit:  0,
		Offset: 0,
	}); err == nil {
		fmt.Println(jsoniter.MarshalToString(campaign))
	} else {
		fmt.Println(err)
	}
}
