package main

import (
	"fmt"
	"net/http"
	"strings"
)

type slackClient struct {
	webHook string
	name    string
	face    string
}

func newSlackClient(webHook string) *slackClient {
	return &slackClient{
		webHook: webHook,
		name:    "Notifier",
		face:    "robot_face"}
}

func (slack *slackClient) Name(name string) {
	slack.name = name
}

func (slack *slackClient) Face(face string) {
	slack.face = face
}

func (slack slackClient) Notify(text string) error {
	json := buildRequest(text, slack)

	req, err := http.NewRequest("POST", slack.webHook, strings.NewReader(json))
	if err != nil {
		return fmt.Errorf("Can't connect to host %s: %s", slack.webHook, err.Error())
	}

	req.Header.Set("Content-Type", "application/json")

	client := http.Client{}
	_, err = client.Do(req)

	return err
}

func buildRequest(text string, slack slackClient) string {
	return fmt.Sprintf(`{"text":"%s", "username": "%s", "icon_emoji": ":%s:"}`, text, slack.name, slack.face)
}
