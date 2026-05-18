-- Enable pg_trgm extension for fuzzy/trigram matching in workflow search.
-- Falls back gracefully if pg_trgm is not available (search uses exact ILIKE).
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_trgm not available — fuzzy search will use exact ILIKE';
END $$;
