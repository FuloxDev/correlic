package model

type AgentLiveness string

const (
	LivenessOnline  AgentLiveness = "online"
	LivenessStale   AgentLiveness = "stale"
	LivenessOffline AgentLiveness = "offline"
)
