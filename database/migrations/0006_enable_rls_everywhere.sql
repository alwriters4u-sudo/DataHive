-- ============================================================================
-- DataHive — enable RLS on every table, deny by default
-- ============================================================================
-- Through Phase 14 only users/messages/notifications had RLS (0002). Every
-- other table had it OFF, so anyone holding the public anon key (it ships to
-- every browser as NEXT_PUBLIC_SUPABASE_ANON_KEY) could call Supabase's REST
-- API directly and read/write ANY row, bypassing AuthzService entirely.
--
-- Fix: RLS on everywhere, no permissive policies. Every service now uses the
-- service-role client (bypasses RLS) AFTER its own AuthzService.can() check,
-- so the app works while direct anon-key access gets nothing.
--
-- Deliberate exceptions:
--  * messages keeps "messages_read_if_participant" from 0002 — ChatPanel
--    subscribes to Realtime with the anon-key browser client, so RLS is the
--    real boundary for who receives live message events.
--  * categories gets a public SELECT policy — no sensitive data, and the
--    marketing/browse pages may read it without a session.
-- ============================================================================

alter table client_profiles enable row level security;
alter table expert_profiles enable row level security;
alter table expert_skills enable row level security;
alter table skills enable row level security;
alter table portfolio_items enable row level security;
alter table certifications enable row level security;
alter table verification_records enable row level security;
alter table categories enable row level security;
alter table commission_rules enable row level security;
alter table projects enable row level security;
alter table project_requirements enable row level security;
alter table project_roles enable row level security;
alter table project_applications enable row level security;
alter table proposals enable row level security;
alter table project_teams enable row level security;
alter table team_members enable row level security;
alter table milestones enable row level security;
alter table tasks enable row level security;
alter table task_comments enable row level security;
alter table files enable row level security;
alter table deliverables enable row level security;
alter table conversations enable row level security;
alter table conversation_participants enable row level security;
alter table message_reads enable row level security;
alter table meetings enable row level security;
alter table meeting_participants enable row level security;
alter table action_items enable row level security;
alter table project_funding enable row level security;
alter table transactions enable row level security;
alter table payouts enable row level security;
alter table invoices enable row level security;
alter table reviews enable row level security;
alter table disputes enable row level security;
alter table dispute_evidence enable row level security;
alter table audit_logs enable row level security;

create policy "categories_public_read" on categories
  for select using (true);
