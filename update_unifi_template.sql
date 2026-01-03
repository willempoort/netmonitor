-- Update UniFi Controller template met suppress_alert_types behavior
-- Voor v2.8 release - direct SQL update

-- Stap 1: Vind UniFi Controller template ID
SELECT id, name, description FROM device_templates WHERE name = 'UniFi Controller';

-- Stap 2: Voeg suppress_alert_types behavior toe (vervang <template_id> met ID uit stap 1)
-- BELANGRIJK: Alleen uitvoeren als de behavior nog niet bestaat!

-- Check eerst of behavior al bestaat:
SELECT * FROM template_behaviors 
WHERE template_id = (SELECT id FROM device_templates WHERE name = 'UniFi Controller')
  AND behavior_type = 'suppress_alert_types';

-- Als bovenstaande query geen resultaten geeft, voer dan deze INSERT uit:
INSERT INTO template_behaviors (template_id, behavior_type, parameters, action, description)
SELECT 
    id,
    'suppress_alert_types',
    '{"alert_types": ["HTTP_SENSITIVE_DATA", "HTTP_HIGH_ENTROPY_PAYLOAD"]}',
    'allow',
    'UniFi management traffic bevat configuratie data die lijkt op sensitive data'
FROM device_templates 
WHERE name = 'UniFi Controller';

-- Verificatie: Check alle behaviors voor UniFi Controller
SELECT 
    t.name as template_name,
    b.behavior_type,
    b.parameters,
    b.description
FROM device_templates t
JOIN template_behaviors b ON b.template_id = t.id
WHERE t.name = 'UniFi Controller'
ORDER BY b.id;
