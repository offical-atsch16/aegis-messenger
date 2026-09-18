-- ==========================================
-- AegisChat Supabase Database Schema & Setup
-- ==========================================

-- Enable pgcrypto for UUID generation if needed
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. TABLE: PROFILES
-- Holds primary user accounts linked 1-to-1 with Supabase Auth users.
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(32) UNIQUE NOT NULL,
    main_number VARCHAR(8) UNIQUE NOT NULL,
    encrypted_private_key JSONB NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. TABLE: DISPOSABLE_NUMBERS (Burner IDs)
-- Temporary numbers linked to a user's profile.
CREATE TABLE IF NOT EXISTS public.disposable_numbers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    burner_number VARCHAR(8) UNIQUE NOT NULL,
    active BOOLEAN DEFAULT TRUE NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. TABLE: MESSAGES
-- Encrypted payload messages routed via main_number or burner_number.
CREATE TABLE IF NOT EXISTS public.messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_number VARCHAR(8) NOT NULL,
    recipient_number VARCHAR(8) NOT NULL,
    encrypted_payload TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (RLS) on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.disposable_numbers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

-- Helper function to fetch all valid numbers owned by current authenticated user
CREATE OR REPLACE FUNCTION public.get_my_numbers()
RETURNS TABLE (number_id VARCHAR(8))
LANGUAGE sql STABLE SECURITY DEFINER AS $$
    SELECT main_number AS number_id FROM public.profiles WHERE id = auth.uid()
    UNION
    SELECT burner_number AS number_id FROM public.disposable_numbers
    WHERE user_id = auth.uid()
      AND active = TRUE
      AND (expires_at IS NULL OR expires_at > NOW());
$$;

-- RLS POLICIES FOR PROFILES
CREATE POLICY "Public profiles are viewable by everyone"
    ON public.profiles FOR SELECT
    USING (true);

CREATE POLICY "Users can insert their own profile"
    ON public.profiles FOR INSERT
    WITH CHECK (auth.uid() = id);

CREATE POLICY "Users can update their own profile"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id);

-- RLS POLICIES FOR DISPOSABLE_NUMBERS
CREATE POLICY "Active disposable numbers are readable by everyone"
    ON public.disposable_numbers FOR SELECT
    USING (true);

CREATE POLICY "Users can insert their own disposable numbers"
    ON public.disposable_numbers FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own disposable numbers"
    ON public.disposable_numbers FOR UPDATE
    USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own disposable numbers"
    ON public.disposable_numbers FOR DELETE
    USING (auth.uid() = user_id);

-- RLS POLICIES FOR MESSAGES
CREATE POLICY "Users can read messages sent by or to their numbers"
    ON public.messages FOR SELECT
    USING (
        sender_number IN (SELECT number_id FROM public.get_my_numbers())
        OR recipient_number IN (SELECT number_id FROM public.get_my_numbers())
    );

CREATE POLICY "Authenticated users can insert messages if sender is their number"
    ON public.messages FOR INSERT
    WITH CHECK (
        sender_number IN (SELECT number_id FROM public.get_my_numbers())
    );

-- ENABLE REALTIME FOR MESSAGES
ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
