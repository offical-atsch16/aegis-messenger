-- =========================================================
-- AegisChat Incremental Database Migration: 005_fix_support_11111111_and_tickets.sql
-- Emergency Fix: Support ID 11111111 Account Provisioning, E2EE Public Key & Support Tickets RLS
-- =========================================================

-- 1. Ensure Columns on Profiles & Messages Tables
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user' NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS share_profile BOOLEAN DEFAULT TRUE NOT NULL;

-- 2. System Support Account (11111111) & Valid WebCrypto ECDH Public Key
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
END $$;

-- 3. Support Tickets Table & Indexes
CREATE TABLE IF NOT EXISTS public.support_tickets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  user_number VARCHAR(8) NOT NULL,
  ticket_status TEXT DEFAULT 'open' NOT NULL,
  status TEXT DEFAULT 'open' NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_support_tickets_user_number ON public.support_tickets(user_number);

-- 4. Enable Row Level Security Policies
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Anyone can manage support tickets" ON public.support_tickets;
CREATE POLICY "Anyone can manage support tickets"
  ON public.support_tickets FOR ALL
  USING (true);
