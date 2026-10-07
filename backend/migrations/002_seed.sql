-- ============================================================================
-- Correlic Backend — Consolidated Seed Data
-- ============================================================================
-- This file replaces seed data from migrations 044, 047, 051, 060, 080, 082.
-- All inserts use ON CONFLICT DO NOTHING so re-running is safe.
--
-- Note: VS Code (code/Code) is intentionally NOT included in AI patterns —
-- it's a general-purpose editor, not an AI agent. AI extensions
-- (copilot, codeium, tabnine, continue) have their own dedicated patterns.
-- ============================================================================

-- ── AI Agent Patterns (process name detection) ──────────────────────────────
-- Substring + case-insensitive match against process comm/exe/cmdline.
-- Note: VS Code (code/Code) is intentionally excluded — it's a general editor.

-- IDEs / VS Code forks
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('cursor',      'cursor',      'Cursor IDE (cursor.exe)'),
    ('Cursor',      'cursor',      'Cursor IDE (Cursor.exe)'),
    ('windsurf',    'windsurf',    'Windsurf IDE (Codeium fork of VS Code)'),
    ('antigravity', 'antigravity', 'Google Antigravity AI IDE'),
    ('zed',         'zed',         'Zed editor (built-in AI agent panel)'),
    ('trae',        'trae',        'ByteDance Trae IDE (VS Code fork)'),
    ('pearai',      'pearai',      'PearAI editor (open-source Cursor alternative)'),
    ('void',        'void',        'Void editor (open-source Cursor alternative)')
ON CONFLICT (pattern) DO NOTHING;

-- CLI agents (standalone binaries)
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('claude',      'claude',      'Claude Code (Anthropic CLI: claude / claude.exe)'),
    ('aider',       'aider',       'Aider CLI (Python pair-programmer)'),
    ('cline',       'cline',       'Cline CLI 2.0 (autonomous coding agent)'),
    ('codex',       'codex',       'OpenAI Codex CLI (codex binary)'),
    ('gemini',      'gemini',      'Google Gemini CLI (gemini binary)'),
    ('goose',       'goose',       'Block Goose CLI (Linux Foundation AAIF)'),
    ('devin',       'devin',       'Cognition Devin CLI (devin run / init)')
ON CONFLICT (pattern) DO NOTHING;

-- VS Code / JetBrains AI extensions and language-server helpers
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('copilot',     'copilot',     'GitHub Copilot (copilot-language-server)'),
    ('codeium',     'codeium',     'Codeium (codeium-language-server)'),
    ('tabnine',     'tabnine',     'TabNine (TabNine.exe / tabnine_binary)'),
    ('continue',    'continue',    'Continue.dev (binary process)'),
    ('supermaven',  'supermaven',  'Supermaven autocomplete')
ON CONFLICT (pattern) DO NOTHING;

-- Python agent frameworks (matched via command line)
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('langchain',   'langchain',   'LangChain framework'),
    ('langgraph',   'langgraph',   'LangChain LangGraph orchestration'),
    ('llamaindex',  'llamaindex',  'LlamaIndex framework'),
    ('autogpt',     'autogpt',     'AutoGPT autonomous agent'),
    ('autogen',     'autogen',     'Microsoft AutoGen multi-agent framework'),
    ('crewai',      'crewai',      'CrewAI multi-agent framework'),
    ('openhands',   'openhands',   'OpenHands (formerly OpenDevin)'),
    ('opendevin',   'openhands',   'OpenDevin (legacy alias for OpenHands)'),
    ('smolagents',  'smolagents',  'HuggingFace SmolAgents'),
    ('agno',        'agno',        'Agno agent framework (formerly Phidata)'),
    ('phidata',     'agno',        'Phidata (legacy name for Agno)'),
    ('metagpt',     'metagpt',     'MetaGPT multi-agent framework'),
    ('babyagi',     'babyagi',     'BabyAGI autonomous task agent')
ON CONFLICT (pattern) DO NOTHING;

-- ── Safe Domains (prevent AI data exfiltration false positives) ─────────────

-- Core LLM API providers
INSERT INTO safe_domains_list (domain, description) VALUES
    ('api.openai.com',                    'OpenAI API'),
    ('openai.com',                        'OpenAI'),
    ('api.anthropic.com',                 'Anthropic API'),
    ('anthropic.com',                     'Anthropic'),
    ('googleapis.com',                    'Google Cloud APIs'),
    ('generativelanguage.googleapis.com', 'Google Gemini API'),
    ('azure.com',                         'Microsoft Azure APIs'),
    ('huggingface.co',                    'HuggingFace Model Hub'),
    ('cohere.com',                        'Cohere API'),
    ('together.ai',                       'Together AI'),
    ('replicate.com',                     'Replicate'),
    ('mistral.ai',                        'Mistral AI'),
    ('groq.com',                          'Groq API'),
    ('api.x.ai',                          'xAI / Grok API'),
    ('api.deepseek.com',                  'DeepSeek API'),
    ('openrouter.ai',                     'OpenRouter API')
ON CONFLICT (domain) DO NOTHING;

-- AI agent vendors / IDE telemetry
INSERT INTO safe_domains_list (domain, description) VALUES
    ('cursor.sh',       'Cursor AI'),
    ('cursorapi.com',   'Cursor API'),
    ('anysphere.co',    'Cursor (Anysphere)'),
    ('aider.chat',      'Aider AI'),
    ('windsurf.com',    'Windsurf AI'),
    ('codeium.com',     'Codeium / Windsurf'),
    ('sourcegraph.com', 'Sourcegraph / Cody'),
    ('tabnine.com',     'Tabnine AI')
ON CONFLICT (domain) DO NOTHING;

-- Source code / package registries
INSERT INTO safe_domains_list (domain, description) VALUES
    ('github.com',                    'GitHub'),
    ('api.github.com',                'GitHub REST API'),
    ('githubusercontent.com',         'GitHub Raw Content'),
    ('raw.githubusercontent.com',     'GitHub raw content'),
    ('objects.githubusercontent.com', 'GitHub release assets'),
    ('githubassets.com',              'GitHub static assets'),
    ('github.io',                     'GitHub Pages'),
    ('npmjs.org',                     'npm package registry'),
    ('registry.npmjs.org',            'npm package registry (direct)'),
    ('pypi.org',                      'Python Package Index'),
    ('files.pythonhosted.org',        'PyPI file downloads'),
    ('crates.io',                     'Rust crate registry'),
    ('rubygems.org',                  'Ruby gem registry'),
    ('pkg.go.dev',                    'Go package discovery'),
    ('proxy.golang.org',              'Go module proxy'),
    ('sum.golang.org',                'Go checksum database'),
    ('golang.org',                    'Go official site'),
    ('repo1.maven.org',               'Maven Central'),
    ('plugins.gradle.org',            'Gradle plugin portal'),
    ('registry.yarnpkg.com',          'Yarn registry'),
    ('cdn.jsdelivr.net',              'jsDelivr CDN'),
    ('unpkg.com',                     'unpkg CDN'),
    ('deno.land',                     'Deno module registry'),
    ('jsr.io',                        'JSR registry'),
    ('api.nuget.org',                 'NuGet package registry'),
    ('docker.io',                     'Docker Hub'),
    ('ghcr.io',                       'GitHub Container Registry'),
    ('mcr.microsoft.com',             'Microsoft Container Registry')
ON CONFLICT (domain) DO NOTHING;

-- Cloud / infrastructure providers
INSERT INTO safe_domains_list (domain, description) VALUES
    ('amazonaws.com',          'Amazon Web Services'),
    ('cloudflare.com',         'Cloudflare CDN'),
    ('cloudflareinsights.com', 'Cloudflare analytics'),
    ('microsoft.com',          'Microsoft services'),
    ('windows.net',            'Azure Storage / services'),
    ('live.com',               'Microsoft auth'),
    ('msftconnecttest.com',    'Windows connectivity check'),
    ('dl.google.com',          'Google downloads'),
    ('google.com',             'Google services'),
    ('googleusercontent.com',  'Google user content / Cloud Run'),
    ('gstatic.com',            'Google static content'),
    ('googlesyndication.com',  'Google ads / analytics'),
    ('googletagmanager.com',   'Google Tag Manager'),
    ('google-analytics.com',   'Google Analytics'),
    ('doubleclick.net',        'Google ads'),
    ('apple.com',              'Apple services'),
    ('icloud.com',             'Apple iCloud'),
    ('akamaized.net',          'Akamai CDN')
ON CONFLICT (domain) DO NOTHING;

-- Developer tooling / VS Code
INSERT INTO safe_domains_list (domain, description) VALUES
    ('vscode-cdn.net',    'VSCode CDN'),
    ('vsassets.io',       'VSCode Marketplace assets'),
    ('visualstudio.com',  'Visual Studio services'),
    ('vo.msecnd.net',     'Microsoft CDN')
ON CONFLICT (domain) DO NOTHING;

-- Observability / analytics (used by AI tools for telemetry)
INSERT INTO safe_domains_list (domain, description) VALUES
    ('sentry.io',       'Error tracking'),
    ('segment.io',      'Analytics'),
    ('segment.com',     'Analytics'),
    ('mixpanel.com',    'Analytics'),
    ('amplitude.com',   'Analytics'),
    ('posthog.com',     'Analytics'),
    ('launchdarkly.com','Feature flags'),
    ('statsig.com',     'Feature flags')
ON CONFLICT (domain) DO NOTHING;
