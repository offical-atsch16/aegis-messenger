-- =========================================================
-- AegisChat Incremental Database Migration: 004_fix_is_disabled_and_unblock_users.sql
-- Emergency Fix: Fix Account Lock Mismatches & Unblock All Existing Accounts
-- =========================================================

-- 1. Ensure `is_disabled` column exists on public.profiles as BOOLEAN DEFAULT false NOT NULL
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT FALSE NOT NULL;

-- 2. Explicitly unlock all existing accounts across profiles
UPDATE public.profiles SET is_disabled = false WHERE is_disabled IS NULL OR is_disabled = true OR is_disabled IS NOT false;

-- 3. Safely update auth.users table if `is_disabled` column exists
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'auth' AND table_name = 'users' AND column_name = 'is_disabled'
  ) THEN
    EXECUTE 'UPDATE auth.users SET is_disabled = false WHERE is_disabled IS NULL OR is_disabled = true;';
  END IF;
EXCEPTION
  WHEN OTHERS THEN NULL;
END $$;
