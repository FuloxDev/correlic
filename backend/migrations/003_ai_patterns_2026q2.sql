-- ============================================================================
-- 003_ai_patterns_2026q2.sql
-- ============================================================================
-- Adds new AI agent patterns released or popularized after the initial 002
-- seed: new IDEs (Zed, Trae, PearAI, Void), new CLI agents (Cline 2.0, Codex,
-- Gemini, Goose, Devin), new Python frameworks (AutoGen, LangGraph, LlamaIndex,
-- OpenHands, SmolAgents, Agno, MetaGPT, BabyAGI), and Supermaven autocomplete.
--
-- Idempotent: ON CONFLICT DO NOTHING. Safe to re-run on any DB state.
-- This file exists separately from 002_seed.sql so existing installs (where
-- 002_seed.sql is already in schema_migrations) pick up the new patterns.
-- ============================================================================

-- New IDEs / VS Code forks
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('zed',         'zed',         'Zed editor (built-in AI agent panel)'),
    ('trae',        'trae',        'ByteDance Trae IDE (VS Code fork)'),
    ('pearai',      'pearai',      'PearAI editor (open-source Cursor alternative)'),
    ('void',        'void',        'Void editor (open-source Cursor alternative)')
ON CONFLICT (pattern) DO NOTHING;

-- New CLI agents
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('cline',       'cline',       'Cline CLI 2.0 (autonomous coding agent)'),
    ('codex',       'codex',       'OpenAI Codex CLI (codex binary)'),
    ('gemini',      'gemini',      'Google Gemini CLI (gemini binary)'),
    ('goose',       'goose',       'Block Goose CLI (Linux Foundation AAIF)'),
    ('devin',       'devin',       'Cognition Devin CLI (devin run / init)')
ON CONFLICT (pattern) DO NOTHING;

-- Extension helper binary
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('supermaven',  'supermaven',  'Supermaven autocomplete')
ON CONFLICT (pattern) DO NOTHING;

-- New Python frameworks
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('langgraph',   'langgraph',   'LangChain LangGraph orchestration'),
    ('llamaindex',  'llamaindex',  'LlamaIndex framework'),
    ('autogen',     'autogen',     'Microsoft AutoGen multi-agent framework'),
    ('openhands',   'openhands',   'OpenHands (formerly OpenDevin)'),
    ('opendevin',   'openhands',   'OpenDevin (legacy alias for OpenHands)'),
    ('smolagents',  'smolagents',  'HuggingFace SmolAgents'),
    ('agno',        'agno',        'Agno agent framework (formerly Phidata)'),
    ('phidata',     'agno',        'Phidata (legacy name for Agno)'),
    ('metagpt',     'metagpt',     'MetaGPT multi-agent framework'),
    ('babyagi',     'babyagi',     'BabyAGI autonomous task agent')
ON CONFLICT (pattern) DO NOTHING;
