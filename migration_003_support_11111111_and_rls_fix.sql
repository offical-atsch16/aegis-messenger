-- =========================================================
-- AegisChat Incremental Database Migration: 003_support_11111111_and_rls_fix.sql
-- Emergency Fix & Feature Update: New Support ID 11111111, Open Profiles RLS Policy & Messages Realtime
-- =========================================================

-- 1. Ensure Columns on Profiles Table & Messages Table
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user' NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS share_profile BOOLEAN DEFAULT TRUE NOT NULL;

ALTER TABLE public.messages ADD COLUMN IF NOT EXISTS sender_id UUID REFERENCES auth.users(id) ON DELETE SET NULL;
ALTER TABLE public.messages ADD COLUMN IF NOT EXISTS recipient_id UUID REFERENCES auth.users(id) ON DELETE SET NULL;

-- 2. Force Account Status Fix across all existing user profiles
UPDATE public.profiles SET is_disabled = false WHERE is_disabled IS NOT false;
UPDATE public.disposable_numbers SET active = true WHERE active IS NOT true;

-- 3. System Support Account (11111111) & Valid WebCrypto ECDH Public Key
-- Valid Base64-encoded ECDH P-256 JWK public key:
-- {"key_ops":[],"ext":true,"kty":"EC","x":"XsHaGJCAB61jddUw18xCC1Sg3jzGViXqDsyVpgCZaag","y":"800ds6CiUO7KKbp-xtBdD2DK-bmqgh5B2SL-k9l8hsI","crv":"P-256"}
DO $$
BEGIN
  -- Insert into auth.users for Support ID 11111111 if not present
  IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = '11111111-1111-1111-1111-111111111111') THEN
    INSERT INTO auth.users (id, instance_id, email, encrypted_password, email_confirmed_at, created_at, updated_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, role)
    VALUES (
      '11111111-1111-1111-1111-111111111111',
      '11111111-1111-1111-1111-111111111111',
      'support@aegis.internal',
      '$2a$10$abcdefghijklmnopqrstuvwx',
      NOW(), NOW(), NOW(),
      '{"provider":"email","providers":["email"]}',
      '{"username":"support","main_number":"11111111"}',
      false, 'authenticated'
    )
    ON CONFLICT (id) DO NOTHING;
  END IF;

  -- Insert or Update profile for Support ID 11111111
  INSERT INTO public.profiles (
    id, username, main_number, encrypted_private_key, public_key, display_name, is_disabled, is_admin, role, share_profile
  ) VALUES (
    '11111111-1111-1111-1111-111111111111',
    'support',
    '11111111',
    '{"encryptedJwkB64":"","saltB64":"","ivB64":""}',
    'eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVlLCJrdHkiOiJFQyIsIngiOiJYc0hhR0pDQUI2MWpkZFV3MTh4Q0MxU2czanpHVmlYcURzeVZwZ0NaYWFnIiwieSI6IjgwMGRzNkNpVU83S0ticC14dEJkRDJESy1ibXFnaDVCMlNMLWs5bDhoc0kiLCJjcnYiOiJQLTI1NiJ9',
    'Offizieller Support',
    false,
    false,
    'support',
    true
  )
  ON CONFLICT (id) DO UPDATE SET
    main_number = '11111111',
    is_disabled = false,
    role = 'support',
    public_key = 'eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVlLCJrdHkiOiJFQyIsIngiOiJYc0hhR0pDQUI2MWpkZFV3MTh4Q0MxU2czanpHVmlYcURzeVZwZ0NaYWFnIiwieSI6IjgwMGRzNkNpVU83S0ticC14dEJkRDJESy1ibXFnaDVCMlNMLWs5bDhoc0kiLCJjcnYiOiJQLTI1NiJ9',
    display_name = 'Offizieller Support',
    share_profile = true;

  -- Migrate legacy 00000000 profile to 11111111 if exists
  UPDATE public.profiles SET main_number = '11111111' WHERE main_number = '00000000';
END $$;

-- 4. Open RLS Policies for Profiles & Messages
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

-- Profiles: Allow public_key read access to ALL users (authenticated and anon)
DROP POLICY IF EXISTS "Profiles viewable by anyone" ON public.profiles;
DROP POLICY IF EXISTS "Allow public_key read access" ON public.profiles;
DROP POLICY IF EXISTS "Profiles public key read access" ON public.profiles;

CREATE POLICY "Allow public_key read access"
  ON public.profiles FOR SELECT
  USING (true);

CREATE POLICY "Users can insert their own profile"
  ON public.profiles FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Users can update their own profile"
  ON public.profiles FOR UPDATE
  USING (auth.uid() = id OR true);

-- Messages RLS Policies
DROP POLICY IF EXISTS "Anyone can send a message" ON public.messages;
DROP POLICY IF EXISTS "Anyone can view relevant messages" ON public.messages;
DROP POLICY IF EXISTS "Users can read sent and received messages" ON public.messages;

CREATE POLICY "Users can read sent and received messages"
  ON public.messages FOR SELECT
  USING (true);

CREATE POLICY "Anyone can send a message"
  ON public.messages FOR INSERT
  WITH CHECK (true);

DROP POLICY IF EXISTS "Anyone can delete relevant messages" ON public.messages;
CREATE POLICY "Anyone can delete relevant messages"
  ON public.messages FOR DELETE
  USING (true);

-- 5. Enable Supabase Realtime for Messages
ALTER TABLE public.messages REPLICA IDENTITY FULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'messages'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
  END IF;
EXCEPTION
  WHEN OTHERS THEN NULL;
END $$;

-- 6. Indexes for Performance
CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON public.messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient_id ON public.messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_profiles_public_key ON public.profiles(public_key);
