-- ============================================================================
-- 006_ai_patterns_2026q4.sql
-- ============================================================================
-- Adds AI coding tools launched or popularised in 2025–2026 that the 002/003
-- seeds do not cover: OpenCode, Sourcegraph Amp, AWS Kiro, Google Jules
-- (Jules Tools CLI), Roo Code, Charm Crush, Factory Droid, Qwen Code,
-- JetBrains Junie, Augment (Auggie CLI), Moonshot Kimi CLI, Codebuff and
-- Plandex, plus the vendor API domains those tools talk to so their traffic
-- is not reported as AI data exfiltration. Goose and Trae are already seeded
-- (002/003); Trae only gains its domain here.
--
-- Idempotent: ON CONFLICT DO NOTHING on the per-org unique indexes that 005
-- introduced (built-in rows have org_id NULL → the zero UUID). Safe to re-run
-- on any DB state. This file exists separately from 002_seed.sql so existing
-- installs (where 002_seed.sql is already in schema_migrations) pick up the
-- new patterns.
--
-- Matching rules (agent/internal/lineage/tracker.go): a pattern must be at
-- least 3 characters and must not contain a dot (domain-style patterns are
-- ignored for process matching). It matches a process when the process name,
-- executable path or argv[0] has a path component equal to the pattern or
-- starting with it followed by "-", "." or "_", or when an argument's final
-- path component matches the same way. Matching is whole-token, never a
-- substring of the command line.
--
-- False-positive notes for the short / generic names (remove a pattern via
-- DELETE /api/v1/ai/agent-patterns/{id} if it misfires in your environment):
--   amp    — also the binary of the AMP (Accelerated Mobile Pages) toolbox
--            and any script named amp.*; a directory named "amp" in an
--            executable path matches too.
--   roo    — Roo Code's VS Code extension runs inside the extension host and
--            has no process of its own; the pattern covers a "roo" binary or
--            script. Any other binary or directory called "roo" matches.
--   crush  — a generic word; any binary or directory named "crush" matches.
--   jules  — a first name: processes whose executable lives under a user
--            directory named "jules" (/home/jules/...) are attributed to
--            Jules. Drop the pattern on hosts with such an account.
--   droid  — matches "droid", "droid-*", "droid.*", "droid_*" (not droidcam
--            or android tooling, whose names continue with a letter).
--   kiro   — matches the Kiro IDE and kiro-cli; no known collisions.
--   augment is intentionally NOT a pattern: "python augment.py" (data
--            augmentation scripts) would be flagged on every ML workstation.
--            Augment is detected through its CLI, auggie.
--   kimi   — Moonshot's Kimi CLI; the name is otherwise rare on servers.
-- ============================================================================

-- CLI agents (standalone binaries)
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('opencode',  'opencode', 'OpenCode terminal agent (opencode binary)'),
    ('amp',       'amp',      'Sourcegraph Amp CLI (amp binary; see false-positive note)'),
    ('jules',     'jules',    'Google Jules Tools CLI (jules binary; see false-positive note)'),
    ('roo',       'roo',      'Roo Code CLI / scripts (roo binary; see false-positive note)'),
    ('crush',     'crush',    'Charm Crush terminal agent (crush binary; see false-positive note)'),
    ('droid',     'droid',    'Factory Droid CLI (droid binary)'),
    ('qwen',      'qwen',     'Qwen Code CLI (qwen / qwen-code binary)'),
    ('auggie',    'augment',  'Augment Code CLI (auggie binary)'),
    ('kimi',      'kimi',     'Moonshot Kimi CLI (kimi binary)'),
    ('codebuff',  'codebuff', 'Codebuff CLI (codebuff binary)'),
    ('plandex',   'plandex',  'Plandex CLI (plandex binary)')
ON CONFLICT (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), pattern) DO NOTHING;

-- IDEs and IDE plugins
INSERT INTO ai_agent_patterns (pattern, agent_type, description) VALUES
    ('kiro',      'kiro',     'AWS Kiro IDE and kiro-cli'),
    ('junie',     'junie',    'JetBrains Junie (plugin helper / scripts named junie; the plugin itself runs inside the IDE JVM)')
ON CONFLICT (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), pattern) DO NOTHING;

-- Vendor API domains (suffix-matched: "qwen.ai" covers portal.qwen.ai).
INSERT INTO safe_domains_list (domain, description) VALUES
    ('opencode.ai',            'OpenCode (Zen model gateway)'),
    ('ampcode.com',            'Sourcegraph Amp'),
    ('kiro.dev',               'AWS Kiro'),
    ('jules.google.com',       'Google Jules'),
    ('roocode.com',            'Roo Code Cloud'),
    ('charm.land',             'Charm (Crush provider catalog)'),
    ('factory.ai',             'Factory Droid'),
    ('qwen.ai',                'Alibaba Qwen (Qwen Code)'),
    ('dashscope.aliyuncs.com', 'Alibaba DashScope API (Qwen Code)'),
    ('trae.ai',                'ByteDance Trae'),
    ('jetbrains.ai',           'JetBrains AI (Junie)'),
    ('augmentcode.com',        'Augment Code'),
    ('moonshot.ai',            'Moonshot AI (Kimi)'),
    ('moonshot.cn',            'Moonshot AI (Kimi, China endpoint)'),
    ('codebuff.com',           'Codebuff'),
    ('plandex.ai',             'Plandex')
ON CONFLICT (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), domain) DO NOTHING;
