package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	linearTeamAndroid = "39dc6884-3753-4b41-ad19-a166a0f2f51d"
	linearTeamiOS     = "6d2402bc-d4bc-4d3d-8f5e-96df51cafe22"
	linearTeamDesktop = "4c83bd23-2236-40b5-a250-88bbc8cc446a"
	linearTeamBridges = "a5b96b19-c49e-4f2a-8372-206eefeba471"
)

const (
	problemChatNetworks   = "Trouble connecting Beeper to a chat network"
	problemSend           = "I can't send a message"
	problemReceiveAny     = "I can't receive any messages"
	problemReceiveCertain = "I can't receive certain messages"
	problemUI             = "Problem with app buttons/interface/text"
	problemEncryption     = "Encryption/decryption error"
	problemNotifications  = "Notifications problem"
	problemFeatureRequest = "Feature request"
	problemBridgeRequest  = "Bridge Request"
	problemOther          = "Other"
)

var appToTeamID = map[string]string{
	"beeper-android": linearTeamAndroid,
	"beeper-ios":     linearTeamiOS,
	"beeper-desktop": linearTeamDesktop,
}

var problemToLabelName = map[string]string{
	problemChatNetworks:   "Chat Networks",
	problemSend:           "User: can't send",
	problemReceiveAny:     "User: can't receive any",
	problemReceiveCertain: "User: can't receive certain",
	problemUI:             "UI",
	problemEncryption:     "User: encryption",
	problemNotifications:  "User: notifications",
	problemFeatureRequest: "User: feature request",
	problemBridgeRequest:  "User: bridge request",
	problemOther:          "User: other",
}

var bridgeToLabelName = map[string]string{
	"android-sms":    "Bridge: Android SMS",
	"androidsms":     "Bridge: Android SMS",
	"discord":        "Bridge: Discord",
	"facebook":       "Bridge: Facebook",
	"googlechat":     "Bridge: Google Chat",
	"instagram":      "Bridge: Instagram",
	"linkedin":       "Bridge: LinkedIn",
	"signal":         "Bridge: Signal",
	"slack":          "Bridge: Slack",
	"telegram":       "Bridge: Telegram",
	"twitter":        "Bridge: Twitter",
	"whatsapp":       "Bridge: WhatsApp",
	"imessage":       "Bridge: iMessage (Mac)",
	"imessage-cloud": "Bridge: iMessage (cloud)",
	"imessagecloud":  "Bridge: iMessage (cloud)",
}

var teamTolabelNameToID map[string]map[string]string

type GraphQLRequest struct {
	Token     string                 `json:"-"`
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type GraphQLError struct {
	Message    string `json:"message"`
	Extensions struct {
		UserPresentableMessage string `json:"userPresentableMessage"`
	}
}

type GraphQLResponse struct {
	Errors []GraphQLError
	Data   json.RawMessage
}

type GetLabelsLabel struct {
	ID   string
	Name string
}

type GetLabelsTeam struct {
	ID     string
	Name   string
	Labels struct {
		Nodes []GetLabelsLabel
	}
}

type GetLabelsResponse struct {
	Teams struct {
		Nodes []GetLabelsTeam
	}
}

type CreateIssueResponse struct {
	IssueCreate struct {
		Success bool
		Issue   struct {
			ID         string
			Title      string
			Identifier string
			URL        string
		}
	}
}

const queryGetLabels = `
query GetLabels {
  teams {
   nodes {
     id
     name
     labels {
       nodes {
         id
         name
       }
     }
   }
  }
}
`

const mutationCreateIssue = `
mutation CreateIssue($input: IssueCreateInput!) {
    issueCreate(input: $input) {
        success
        issue {
            id
            title
            identifier
            url
        }
    }
}
`

func LinearRequest(payload *GraphQLRequest, into interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(payload)
	if err != nil {
		return fmt.Errorf("failed to encode request JSON: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.linear.app/graphql", &buf)
	if err != nil {
		return fmt.Errorf("failed to create GraphQL request: %w", err)
	}
	req.Header.Add("Authorization", payload.Token)
	req.Header.Add("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send GraphQL request: %w", err)
	}
	defer resp.Body.Close()
	var respData GraphQLResponse
	data, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s\n", data)
	err = json.Unmarshal(data, &respData)
	//err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response JSON (status %d): %w", resp.StatusCode, err)
	}
	if len(respData.Errors) > 0 {
		if len(respData.Errors[0].Extensions.UserPresentableMessage) > 0 {
			return fmt.Errorf("GraphQL error: %s", respData.Errors[0].Extensions.UserPresentableMessage)
		}
		return fmt.Errorf("GraphQL error: %s", respData.Errors[0].Message)
	}
	if into != nil {
		err = json.Unmarshal(respData.Data, &into)
		if err != nil {
			return fmt.Errorf("failed to unmarshal response data: %w", err)
		}
	}
	return nil
}

func fillLinearLabels(token string) error {
	var labelResp GetLabelsResponse
	err := LinearRequest(&GraphQLRequest{
		Token: token,
		Query: queryGetLabels,
	}, &labelResp)
	if err != nil {
		return err
	}
	teamTolabelNameToID = make(map[string]map[string]string)
	for _, team := range labelResp.Teams.Nodes {
		labelNameToID := make(map[string]string)
		teamTolabelNameToID[team.ID] = labelNameToID
		for _, label := range team.Labels.Nodes {
			labelNameToID[label.Name] = label.ID
			fmt.Println(team.Name, label.Name, label.ID)
		}
	}
	return nil
}
