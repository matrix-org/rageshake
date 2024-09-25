package main

import (
	"encoding/json"
	"net/url"
	"strconv"
	"time"
)

type grafanaQuery struct {
	Expr      string `json:"expr"`
	QueryType string `json:"queryType"`
}

type grafanaRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type grafanaRequest struct {
	Datasource string         `json:"datasource"`
	Queries    []grafanaQuery `json:"queries"`
	Range      grafanaRange   `json:"range"`
}

func makeGrafanaLogURL(expr string) (string, error) {
	now := time.Now().UTC()
	from := now.Add(-time.Minute * 15)
	to := now.Add(time.Minute * 15)

	req := grafanaRequest{
		Datasource: "f21b0c24-8614-42eb-827b-fcbd230dd8d3",
		Queries:    []grafanaQuery{{expr, "range"}},
		Range: grafanaRange{
			From: strconv.Itoa(int(from.UnixMilli())),
			To:   strconv.Itoa(int(to.UnixMilli())),
		},
	}

	jsonStr, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return "https://grafana.beeper-tools.com/explore?orgId=1&left=" + url.QueryEscape(string(jsonStr)), nil
}

func makeGrafanaLogsURLs(username string) (string, string, error) {
	bridgeLogsURL, err := makeGrafanaLogURL(`{user_id="@` + username + `:beeper.com",app="bridges",env="prod"} | unpack`)
	if err != nil {
		return "", "", err
	}

	megahungryLogsURL, err := makeGrafanaLogURL(`{user_id="@` + username + `:beeper.com",namespace="megahungry",env="prod"} | unpack`)
	if err != nil {
		return "", "", err
	}

	return bridgeLogsURL, megahungryLogsURL, nil
}
