-- Fix corrupted template behavior parameters
-- This fixes cases where {"low_bandwidth":true} became {"{\"low_bandwidth\":true}":true}

DO $$
DECLARE
    behavior_record RECORD;
    params_json jsonb;
    fixed_params jsonb;
    corrupted_key text;
    parsed_json jsonb;
    fixed_count integer := 0;
BEGIN
    -- Loop through all template behaviors
    FOR behavior_record IN
        SELECT id, behavior_type, parameters::jsonb as params
        FROM template_behaviors
        WHERE parameters IS NOT NULL
    LOOP
        -- Check if any keys look like JSON strings (start with '{' and end with '}')
        params_json := behavior_record.params;
        fixed_params := '{}'::jsonb;

        -- Check each key in the parameters
        FOR corrupted_key IN
            SELECT jsonb_object_keys(params_json) as key
        LOOP
            -- If key starts with { and ends with }, it might be corrupted JSON
            IF corrupted_key LIKE '{%}' THEN
                BEGIN
                    -- Try to parse the key as JSON
                    parsed_json := corrupted_key::jsonb;

                    -- If successful, merge it into fixed_params
                    fixed_params := fixed_params || parsed_json;

                    RAISE NOTICE 'Fixed corrupted behavior ID % (%): Parsed key "%"',
                        behavior_record.id, behavior_record.behavior_type, corrupted_key;

                    fixed_count := fixed_count + 1;

                EXCEPTION WHEN OTHERS THEN
                    -- If parsing fails, keep the original key-value pair
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

        -- Update if we fixed something
        IF fixed_params IS DISTINCT FROM params_json THEN
            UPDATE template_behaviors
            SET parameters = fixed_params
            WHERE id = behavior_record.id;
        END IF;
    END LOOP;

    IF fixed_count > 0 THEN
        RAISE NOTICE 'Fixed % corrupted behavior(s)', fixed_count;
    ELSE
        RAISE NOTICE 'No corrupted behaviors found';
    END IF;
END $$;
