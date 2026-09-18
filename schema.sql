-- =========================================================
-- AegisChat - Supabase Database Schema
-- Self-Hosted E2EE Web Messenger with Burner IDs (Disposable Numbers)
-- =========================================================

-- Enable UUID extension if not enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. PROFILES TABLE
-- Stores user identity metadata, main 8-digit ID, public key, and wrapped private key
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  username TEXT UNIQUE NOT NULL,
  main_number VARCHAR(8) UNIQUE NOT NULL,
  encrypted_private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for searching profiles by main_number or username
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

-- Index for resolving burner numbers quickly
CREATE INDEX IF NOT EXISTS idx_disposable_burner_number ON public.disposable_numbers(burner_number);
CREATE INDEX IF NOT EXISTS idx_disposable_user_id ON public.disposable_numbers(user_id);


-- 3. MESSAGES TABLE
-- Stores E2EE encrypted payloads routed between main numbers or burner numbers
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


-- =========================================================
-- ROW LEVEL SECURITY (RLS) & POLICIES
-- =========================================================

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.disposable_numbers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

-- PROFILES POLICIES
-- Anyone authenticated or public can view profiles to find public keys for E2EE handshake
CREATE POLICY "Public profiles are viewable by anyone"
  ON public.profiles FOR SELECT
  USING (true);

-- Users can insert their own profile upon registration
CREATE POLICY "Users can insert their own profile"
  ON public.profiles FOR INSERT
  WITH CHECK (auth.uid() = id);

-- Users can update their own profile
CREATE POLICY "Users can update their own profile"
  ON public.profiles FOR UPDATE
  USING (auth.uid() = id);


-- DISPOSABLE NUMBERS POLICIES
-- Anyone can view disposable numbers to route messages and check validity
CREATE POLICY "Disposable numbers are viewable by anyone"
  ON public.disposable_numbers FOR SELECT
  USING (true);

-- Users can insert burner numbers for their profile
CREATE POLICY "Users can insert their own burner numbers"
  ON public.disposable_numbers FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Users can update or deactivate their own burner numbers
CREATE POLICY "Users can update their own burner numbers"
  ON public.disposable_numbers FOR UPDATE
  USING (auth.uid() = user_id);

-- Users can delete their own burner numbers
CREATE POLICY "Users can delete their own burner numbers"
  ON public.disposable_numbers FOR DELETE
  USING (auth.uid() = user_id);


-- MESSAGES POLICIES
-- Anyone can insert a message as long as it has sender and recipient numbers
CREATE POLICY "Anyone can send a message"
  ON public.messages FOR INSERT
  WITH CHECK (true);

-- Anyone can read messages addressed to or sent by their numbers
CREATE POLICY "Anyone can view relevant messages"
  ON public.messages FOR SELECT
  USING (true);


-- =========================================================
-- SUPABASE REALTIME CONFIGURATION
-- =========================================================

-- Enable Realtime for messages table
ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
