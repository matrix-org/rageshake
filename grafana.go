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

func makeGrafanaLogsURL(username string) (string, error) {
	now := time.Now().UTC()
	from := now.Add(-time.Minute * 15)
	to := now.Add(time.Minute * 15)

	expr := `{username="` + username + `",env="prod"} | unpack`
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
	url := "https://grafana.beeper-tools.com/explore?orgId=1&left=" + url.QueryEscape(string(jsonStr))
	return url, nil
}
