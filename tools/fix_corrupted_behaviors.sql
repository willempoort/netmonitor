-- Fix corrupted template behavior parameters
-- This fixes cases where {"low_bandwidth":true} became {"{\"low_bandwidth\":true}":true}
-- and other variants with escaped quotes and malformed JSON keys

DO $$
DECLARE
    behavior_record RECORD;
    params_json jsonb;
    fixed_params jsonb;
    corrupted_key text;
    fixed_count integer := 0;
    is_corrupted boolean;
    cleaned_key text;
    key_name text;
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
            -- Detect corruption: keys with escaped quotes, starting with {, or containing strange patterns
            IF corrupted_key LIKE '{%' OR
               corrupted_key LIKE '%\"%' OR
               corrupted_key LIKE '"%}%' OR
               corrupted_key LIKE '"{%' OR
               corrupted_key ~ '\\' THEN

                is_corrupted := true;
                RAISE NOTICE 'Found corrupted key in behavior ID %: "%"', behavior_record.id, corrupted_key;

                -- Simple cleanup: extract the actual key name from patterns like:
                -- "\"continuous\": true}" → continuous
                -- "{\"high_bandwidth\": true" → high_bandwidth
                -- "\"streaming\": true" → streaming

                cleaned_key := corrupted_key;

                -- Remove all backslashes
                cleaned_key := replace(cleaned_key, E'\\', '');

                -- Remove all double quotes
                cleaned_key := replace(cleaned_key, '"', '');

                -- Remove leading/trailing braces
                cleaned_key := trim(both '{' from cleaned_key);
                cleaned_key := trim(both '}' from cleaned_key);

                -- If it contains a colon, take only the part before it
                IF position(':' in cleaned_key) > 0 THEN
                    key_name := split_part(cleaned_key, ':', 1);
                ELSE
                    key_name := cleaned_key;
                END IF;

                -- Trim any whitespace
                key_name := trim(key_name);

                -- Validate it's a reasonable property name
                IF key_name ~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
                    -- Add this property as true
                    fixed_params := jsonb_set(fixed_params, ARRAY[key_name], 'true'::jsonb);
                    RAISE NOTICE '  ✓ Extracted property: % → %', corrupted_key, key_name;
                ELSE
                    -- Could not extract valid name, skip it
                    RAISE NOTICE '  ⚠ Could not extract valid name from: %', corrupted_key;
                END IF;

            ELSE
                -- Normal key, keep it with its value
                fixed_params := jsonb_set(
                    fixed_params,
                    ARRAY[corrupted_key],
                    params_json->corrupted_key
                );
            END IF;
        END LOOP;

        -- Update if we found corruption
        IF is_corrupted THEN
            RAISE NOTICE '  → Updating behavior ID % from % to %',
                behavior_record.id, params_json, fixed_params;

            UPDATE template_behaviors
            SET parameters = fixed_params
            WHERE id = behavior_record.id;

            fixed_count := fixed_count + 1;
        END IF;
    END LOOP;

    IF fixed_count > 0 THEN
        RAISE NOTICE '';
        RAISE NOTICE '✅ Fixed % corrupted behavior(s)', fixed_count;
    ELSE
        RAISE NOTICE '';
        RAISE NOTICE 'No corrupted behaviors found';
    END IF;
END $$;
