-- Fix corrupted template behavior parameters
-- This fixes cases where {"low_bandwidth":true} became {"{\"low_bandwidth\":true}":true}
-- and other variants with escaped quotes and malformed JSON keys

DO $$
DECLARE
    behavior_record RECORD;
    params_json jsonb;
    fixed_params jsonb;
    corrupted_key text;
    key_count integer;
    fixed_count integer := 0;
    is_corrupted boolean;
BEGIN
    -- Loop through all template behaviors
    FOR behavior_record IN
        SELECT id, behavior_type, parameters::jsonb as params
        FROM template_behaviors
        WHERE parameters IS NOT NULL
    LOOP
        params_json := behavior_record.params;
        fixed_params := '{}'::jsonb;
        is_corrupted := false;

        -- Check each key in the parameters
        FOR corrupted_key IN
            SELECT jsonb_object_keys(params_json) as key
        LOOP
            -- Detect corruption: keys with escaped quotes, starting with {, or containing \":
            IF corrupted_key LIKE '{%' OR
               corrupted_key LIKE '%\\"%' OR
               corrupted_key LIKE '%}"%' OR
               corrupted_key LIKE '"{%' THEN

                is_corrupted := true;

                RAISE NOTICE 'Found corrupted key in behavior ID % (%): "%"',
                    behavior_record.id, behavior_record.behavior_type, corrupted_key;

                -- Try multiple cleanup strategies
                DECLARE
                    cleaned_key text;
                    parsed_json jsonb;
                BEGIN
                    -- Strategy 1: Try to parse as JSON directly
                    BEGIN
                        parsed_json := corrupted_key::jsonb;
                        IF jsonb_typeof(parsed_json) = 'object' THEN
                            fixed_params := fixed_params || parsed_json;
                            RAISE NOTICE '  ✓ Parsed as complete JSON object';
                            CONTINUE;
                        END IF;
                    EXCEPTION WHEN OTHERS THEN
                        -- Not valid JSON, try next strategy
                    END;

                    -- Strategy 2: Remove wrapping quotes and closing brace/quote patterns
                    cleaned_key := corrupted_key;
                    cleaned_key := regexp_replace(cleaned_key, '^"?\{', '{', 'g');  -- Remove leading "{
                    cleaned_key := regexp_replace(cleaned_key, '\}"?$', '}', 'g');  -- Remove trailing }"
                    cleaned_key := replace(cleaned_key, '\"', '"');  -- Unescape quotes

                    BEGIN
                        parsed_json := cleaned_key::jsonb;
                        IF jsonb_typeof(parsed_json) = 'object' THEN
                            fixed_params := fixed_params || parsed_json;
                            RAISE NOTICE '  ✓ Cleaned and parsed: %', cleaned_key;
                            CONTINUE;
                        END IF;
                    EXCEPTION WHEN OTHERS THEN
                        -- Still not valid, try next strategy
                    END;

                    -- Strategy 3: Try to reconstruct from key pattern like "\"key\": true}"
                    IF corrupted_key LIKE '%\":%' THEN
                        -- Extract the key name and try to rebuild
                        cleaned_key := regexp_replace(corrupted_key, '^"?\\?"?', '', 'g');  -- Remove leading quotes/escapes
                        cleaned_key := regexp_replace(corrupted_key, '\\?"?"?:.*$', '', 'g');  -- Remove everything after key

                        -- Extract just the property name if we can
                        IF cleaned_key ~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
                            -- Valid property name, set to true
                            fixed_params := jsonb_set(fixed_params, ARRAY[cleaned_key], 'true'::jsonb);
                            RAISE NOTICE '  ✓ Extracted property: %', cleaned_key;
                            CONTINUE;
                        END IF;
                    END IF;

                    -- Strategy 4: If all else fails, try to preserve as-is with value
                    RAISE NOTICE '  ⚠ Could not clean key, preserving with value';
                    fixed_params := jsonb_set(
                        fixed_params,
                        ARRAY[corrupted_key],
                        params_json->corrupted_key
                    );
                END;
            ELSE
                -- Normal key, keep it
                fixed_params := jsonb_set(
                    fixed_params,
                    ARRAY[corrupted_key],
                    params_json->corrupted_key
                );
            END IF;
        END LOOP;

        -- Update if we found corruption
        IF is_corrupted THEN
            UPDATE template_behaviors
            SET parameters = fixed_params
            WHERE id = behavior_record.id;

            fixed_count := fixed_count + 1;
            RAISE NOTICE '→ Fixed behavior ID % with parameters: %', behavior_record.id, fixed_params;
        END IF;
    END LOOP;

    IF fixed_count > 0 THEN
        RAISE NOTICE '';
        RAISE NOTICE '✅ Fixed % corrupted behavior(s)', fixed_count;
    ELSE
        RAISE NOTICE 'No corrupted behaviors found';
    END IF;
END $$;
