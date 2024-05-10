package main

import "testing"

func TestConfigRejectionCondition(t *testing.T) {
	cfg := config{
		RejectionConditions: []RejectionCondition{
			{
				App:     "my-app",
				Version: "0.1.0",
			},
			{
				App:   "my-app",
				Label: "0.1.1",
			},
			{
				App:     "my-app",
				Version: "0.1.2",
				Label:   "nightly",
			},
		},
	}
	rejectPayloads := []payload{
		{
			AppName: "my-app",
			Data: map[string]string{
				"Version": "0.1.0",
			},
		},
		{
			AppName: "my-app",
			Data:    map[string]string{},
			Labels:  []string{"0.1.1"},
		},
		{
			AppName: "my-app",
			Labels:  []string{"foo", "nightly"},
			Data: map[string]string{
				"Version": "0.1.2",
			},
		},
	}
	for _, p := range rejectPayloads {
		if !cfg.matchesRejectionCondition(&p) {
			t.Errorf("payload was accepted when it should be rejected:\n payload=%+v\nconfig=%+v", p, cfg)
		}
	}
	acceptPayloads := []payload{
		{
			AppName: "different-app",
			Data: map[string]string{
				"Version": "0.1.0",
			},
		},
		{
			AppName: "different-app",
			Data:    map[string]string{},
			Labels:  []string{"0.1.1"},
		},
		{
			AppName: "different-app",
			Labels:  []string{"foo", "nightly"},
			Data: map[string]string{
				"Version": "0.1.2",
			},
		},
		{
			AppName: "my-app",
			Data: map[string]string{
				"Version": "0.1.0-suffix",
			},
		},
		{
			AppName: "my-app",
			Data:    map[string]string{},
			Labels:  []string{"0.1.1-suffix"},
		},
		{
			AppName: "my-app",
			Labels:  []string{"foo", "nightly-suffix"},
			Data: map[string]string{
				"Version": "0.1.2",
			},
		},
		{ // version matches but label does not (it's Label AND Version not OR)
			AppName: "my-app",
			Labels:  []string{"foo"},
			Data: map[string]string{
				"Version": "0.1.2",
			},
		},
	}
	for _, p := range acceptPayloads {
		if cfg.matchesRejectionCondition(&p) {
			t.Errorf("payload was rejected when it should be accepted:\n payload=%+v\nconfig=%+v", p, cfg)
		}
	}
}
