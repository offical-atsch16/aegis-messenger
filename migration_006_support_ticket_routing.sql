-- =========================================================
-- AegisChat Incremental Database Migration: 006_support_ticket_routing.sql
-- Emergency Fix: Support Ticket Routing, Message Storage & Clean RLS Policies
-- =========================================================

-- 1. Ensure Columns on support_tickets Table
ALTER TABLE public.support_tickets ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE;
ALTER TABLE public.support_tickets ADD COLUMN IF NOT EXISTS user_number VARCHAR(8);
ALTER TABLE public.support_tickets ADD COLUMN IF NOT EXISTS message TEXT;
ALTER TABLE public.support_tickets ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'open' NOT NULL;
ALTER TABLE public.support_tickets ADD COLUMN IF NOT EXISTS ticket_status TEXT DEFAULT 'open' NOT NULL;
ALTER TABLE public.support_tickets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL;
ALTER TABLE public.support_tickets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL;

CREATE INDEX IF NOT EXISTS idx_support_tickets_user_id ON public.support_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_user_number ON public.support_tickets(user_number);

-- 2. Enable Row Level Security (RLS) & Clean Policies
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Anyone can manage support tickets" ON public.support_tickets;
DROP POLICY IF EXISTS "Users can view own tickets" ON public.support_tickets;
DROP POLICY IF EXISTS "Users can create own tickets" ON public.support_tickets;
DROP POLICY IF EXISTS "Admins can update all tickets" ON public.support_tickets;

-- Users can view their own tickets; Admins can view all
CREATE POLICY "Users can view own tickets"
  ON public.support_tickets FOR SELECT
  USING (
    auth.uid() = user_id
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE profiles.id = auth.uid() AND (profiles.role = 'admin' OR profiles.is_admin = true)
    )
  );

-- Users can create their own tickets; Admins can create tickets
CREATE POLICY "Users can create own tickets"
  ON public.support_tickets FOR INSERT
  WITH CHECK (
    auth.uid() = user_id
    OR auth.uid() IS NULL
    OR EXISTS (
      SELECT 1 FROM public.profiles
      WHERE profiles.id = auth.uid() AND (profiles.role = 'admin' OR profiles.is_admin = true)
    )
  );

-- Admins can update all tickets
CREATE POLICY "Admins can update all tickets"
  ON public.support_tickets FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE profiles.id = auth.uid() AND (profiles.role = 'admin' OR profiles.is_admin = true)
    )
  );
