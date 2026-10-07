package model

type AgentState string

const (
	StateStarting AgentState = "starting"
	StateRunning  AgentState = "running"
	StateStopping AgentState = "stopping"
	StateStopped  AgentState = "stopped"
)
