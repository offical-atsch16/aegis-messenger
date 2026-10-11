-- =========================================================
-- AegisChat Incremental Database Migration: 007_persistent_messages_and_purge.sql
-- Persistent Message Storage, Realtime Replication & 23:59 Server-Wipe Cron
-- =========================================================

-- 1. Ensure Table Structure & Indexes for Messages
CREATE TABLE IF NOT EXISTS public.messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_number VARCHAR(8) NOT NULL,
  recipient_number VARCHAR(8) NOT NULL,
  encrypted_payload TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient_number ON public.messages(recipient_number);
CREATE INDEX IF NOT EXISTS idx_messages_sender_number ON public.messages(sender_number);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON public.messages(created_at);

-- 2. Ensure Row Level Security (RLS) & Clean Messages Policies
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Anyone can send a message" ON public.messages;
DROP POLICY IF EXISTS "Anyone can view relevant messages" ON public.messages;
DROP POLICY IF EXISTS "Anyone can delete relevant messages" ON public.messages;

CREATE POLICY "Anyone can send a message"
  ON public.messages FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Anyone can view relevant messages"
  ON public.messages FOR SELECT
  USING (true);

CREATE POLICY "Anyone can delete relevant messages"
  ON public.messages FOR DELETE
  USING (true);

-- 3. Configure Supabase Realtime CDC Replication
ALTER TABLE public.messages REPLICA IDENTITY FULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime' AND schemaname = 'public' AND tablename = 'messages'
    ) THEN
      ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
    END IF;
  END IF;
END $$;

-- 4. Automatic 23:59 Server-Wipe (Data Purge Function)
CREATE OR REPLACE FUNCTION purge_daily_messages()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Irrevocably purge all message history for zero-knowledge compliance
  DELETE FROM public.messages;
END;
$$;

-- 5. Schedule pg_cron Trigger for 23:59 UTC Wipe (if pg_cron extension is available)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    PERFORM cron.schedule(
      'daily_2359_server_wipe',
      '59 23 * * *',
      'SELECT purge_daily_messages()'
    );
  END IF;
EXCEPTION
  WHEN OTHERS THEN
    NULL;
END $$;
