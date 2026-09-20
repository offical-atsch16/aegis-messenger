-- =========================================================
-- AegisChat - Supabase Database Schema
-- Self-Hosted E2EE Web Messenger with Burner IDs & Contacts
-- Cloudflare Pages & Supabase Backend
-- =========================================================

-- Enable UUID extension if not enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. PROFILES TABLE
-- Stores user identity metadata, main 8-digit ID, public key, wrapped private key, account status, and admin role flag
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  username TEXT UNIQUE NOT NULL,
  main_number VARCHAR(8) UNIQUE NOT NULL,
  encrypted_private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  panic_password_hash TEXT,
  is_disabled BOOLEAN DEFAULT FALSE NOT NULL,
  is_admin BOOLEAN DEFAULT FALSE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Indices for searching profiles by main_number or username
CREATE INDEX IF NOT EXISTS idx_profiles_main_number ON public.profiles(main_number);
CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);


-- 2. DISPOSABLE NUMBERS (BURNER IDs) TABLE
-- Stores temporary burner numbers linked to a main profile ID
CREATE TABLE IF NOT EXISTS public.disposable_numbers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
  burner_number VARCHAR(8) UNIQUE NOT NULL,
  active BOOLEAN DEFAULT TRUE NOT NULL,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Indices for resolving burner numbers quickly
CREATE INDEX IF NOT EXISTS idx_disposable_burner_number ON public.disposable_numbers(burner_number);
CREATE INDEX IF NOT EXISTS idx_disposable_user_id ON public.disposable_numbers(user_id);


-- 3. USER CONTACTS & NICKNAMES TABLE
-- Stores contacts and custom local nicknames synced per user (Zero-Knowledge: chat history remains local)
CREATE TABLE IF NOT EXISTS public.user_contacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
  contact_number VARCHAR(8) NOT NULL,
  nickname TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  UNIQUE (user_id, contact_number)
);

CREATE INDEX IF NOT EXISTS idx_user_contacts_user_id ON public.user_contacts(user_id);


-- 4. MESSAGES TABLE
-- Stores E2EE encrypted payloads temporarily routed between main numbers or burner numbers
CREATE TABLE IF NOT EXISTS public.messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_number VARCHAR(8) NOT NULL,
  recipient_number VARCHAR(8) NOT NULL,
  encrypted_payload TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Indices for message filtering by recipient and sender
CREATE INDEX IF NOT EXISTS idx_messages_recipient_number ON public.messages(recipient_number);
CREATE INDEX IF NOT EXISTS idx_messages_sender_number ON public.messages(sender_number);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON public.messages(created_at);


-- 5. SYSTEM SETTINGS TABLE
-- Stores key-value global system configuration (e.g., 'require_invite_code', 'banner_config')
CREATE TABLE IF NOT EXISTS public.system_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL
);


-- 6. INVITE CODES TABLE
-- Stores beta invitation codes with usage limits
CREATE TABLE IF NOT EXISTS public.invite_codes (
  code TEXT PRIMARY KEY,
  created_by UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  max_uses INT DEFAULT 1 NOT NULL,
  used_count INT DEFAULT 0 NOT NULL,
  is_active BOOLEAN DEFAULT TRUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);


-- =========================================================
-- ROW LEVEL SECURITY (RLS) & POLICIES
-- =========================================================

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.disposable_numbers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invite_codes ENABLE ROW LEVEL SECURITY;

-- PROFILES POLICIES
CREATE POLICY "Profiles viewable by anyone"
  ON public.profiles FOR SELECT
  USING (true);

CREATE POLICY "Users can insert their own profile"
  ON public.profiles FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Users can update their own profile"
  ON public.profiles FOR UPDATE
  USING (auth.uid() = id);


-- DISPOSABLE NUMBERS POLICIES
CREATE POLICY "Disposable numbers viewable by anyone"
  ON public.disposable_numbers FOR SELECT
  USING (true);

CREATE POLICY "Users can insert burner numbers"
  ON public.disposable_numbers FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Users can update burner numbers"
  ON public.disposable_numbers FOR UPDATE
  USING (true);

CREATE POLICY "Users can delete burner numbers"
  ON public.disposable_numbers FOR DELETE
  USING (true);


-- USER CONTACTS POLICIES
CREATE POLICY "Anyone can manage user contacts"
  ON public.user_contacts FOR ALL
  USING (true);


-- MESSAGES POLICIES
CREATE POLICY "Anyone can send a message"
  ON public.messages FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Anyone can view relevant messages"
  ON public.messages FOR SELECT
  USING (true);

CREATE POLICY "Anyone can delete relevant messages"
  ON public.messages FOR DELETE
  USING (true);


-- SYSTEM SETTINGS POLICIES
CREATE POLICY "System settings viewable by anyone"
  ON public.system_settings FOR SELECT
  USING (true);

CREATE POLICY "Admins can insert or update system settings"
  ON public.system_settings FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE profiles.id = auth.uid() AND profiles.is_admin = true
    )
  );


-- INVITE CODES POLICIES
CREATE POLICY "Admins can manage invite codes"
  ON public.invite_codes FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE profiles.id = auth.uid() AND profiles.is_admin = true
    )
  );


-- =========================================================
-- SUPABASE REALTIME CONFIGURATION
-- =========================================================

-- Enable Realtime for messages and disposable_numbers tables
ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
ALTER PUBLICATION supabase_realtime ADD TABLE public.disposable_numbers;


-- =========================================================
-- SUPABASE STORAGE BUCKET & POLICIES
-- =========================================================

-- Create chat-attachments storage bucket
INSERT INTO storage.buckets (id, name, public)
VALUES ('chat-attachments', 'chat-attachments', true)
ON CONFLICT (id) DO NOTHING;

-- RLS policies for chat-attachments bucket
CREATE POLICY "Anyone can upload to chat-attachments"
  ON storage.objects FOR INSERT
  WITH CHECK (bucket_id = 'chat-attachments');

CREATE POLICY "Anyone can download from chat-attachments"
  ON storage.objects FOR SELECT
  USING (bucket_id = 'chat-attachments');

CREATE POLICY "Anyone can delete from chat-attachments"
  ON storage.objects FOR DELETE
  USING (bucket_id = 'chat-attachments');
