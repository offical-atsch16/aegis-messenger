-- =========================================================
-- AegisChat Incremental Database Migration: 001_emergency_support_rbac.sql
-- Incremental updates for Support ID (00000000), RLS Repair, RBAC & Indexes
-- =========================================================

-- 1. Ensure Columns on Profiles Table
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user' NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS share_profile BOOLEAN DEFAULT TRUE NOT NULL;

-- 2. System Support Account (00000000)
-- Insert or ensure the 00000000 support user profile exists, active, role='support'
DO $$
BEGIN
  -- Insert into auth.users if not present
  IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = '00000000-0000-0000-0000-000000000000') THEN
    INSERT INTO auth.users (id, instance_id, email, encrypted_password, email_confirmed_at, created_at, updated_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, role)
    VALUES (
      '00000000-0000-0000-0000-000000000000',
      '00000000-0000-0000-0000-000000000000',
      'support@aegis.internal',
      '$2a$10$abcdefghijklmnopqrstuvwx',
      NOW(), NOW(), NOW(),
      '{"provider":"email","providers":["email"]}',
      '{"username":"support","main_number":"00000000"}',
      false, 'authenticated'
    )
    ON CONFLICT (id) DO NOTHING;
  END IF;

  -- Insert/Update profile for 00000000
  INSERT INTO public.profiles (
    id, username, main_number, encrypted_private_key, public_key, display_name, is_disabled, is_admin, role, share_profile
  ) VALUES (
    '00000000-0000-0000-0000-000000000000',
    'support',
    '00000000',
    '{"encryptedJwkB64":"","saltB64":"","ivB64":""}',
    'eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ik00X3M5c1dDRjU5alMzc2pXZGpmbmU0enQydGFpTW41cUpnNDNkVVd4NVEiLCJ5IjoiUnpyeGZ3MWgzaFZEV2UtaE1kR24tQ3ZzOGxMdmN1ZmtmNFdGVDAtbmJvUSJ9',
    'Offizieller Support',
    false,
    false,
    'support',
    true
  )
  ON CONFLICT (id) DO UPDATE SET
    main_number = '00000000',
    is_disabled = false,
    role = 'support',
    display_name = 'Offizieller Support',
    share_profile = true;
END $$;

-- 3. Repair Row Level Security (RLS) Policies on Profiles and Messages
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

-- Drop existing restrictive policies if necessary
DROP POLICY IF EXISTS "Profiles viewable by anyone" ON public.profiles;
CREATE POLICY "Profiles viewable by anyone"
  ON public.profiles FOR SELECT
  USING (true);

DROP POLICY IF EXISTS "Anyone can send a message" ON public.messages;
CREATE POLICY "Anyone can send a message"
  ON public.messages FOR INSERT
  WITH CHECK (true);

DROP POLICY IF EXISTS "Anyone can view relevant messages" ON public.messages;
CREATE POLICY "Anyone can view relevant messages"
  ON public.messages FOR SELECT
  USING (true);

DROP POLICY IF EXISTS "Anyone can delete relevant messages" ON public.messages;
CREATE POLICY "Anyone can delete relevant messages"
  ON public.messages FOR DELETE
  USING (true);

-- 4. Enable Supabase Realtime for Messages & Support Tickets
ALTER TABLE public.messages REPLICA IDENTITY FULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'messages'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'support_tickets'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.support_tickets;
  END IF;
EXCEPTION
  WHEN OTHERS THEN NULL;
END $$;

-- 5. Missing Indexes for Performance Optimization
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_profiles_is_disabled ON public.profiles(is_disabled);
CREATE INDEX IF NOT EXISTS idx_profiles_main_number ON public.profiles(main_number);
CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);
CREATE INDEX IF NOT EXISTS idx_messages_recipient_number ON public.messages(recipient_number);
CREATE INDEX IF NOT EXISTS idx_messages_sender_number ON public.messages(sender_number);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON public.messages(created_at);
CREATE INDEX IF NOT EXISTS idx_support_tickets_user_number ON public.support_tickets(user_number);
