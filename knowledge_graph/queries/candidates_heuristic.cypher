// Label-free selection of security-relevant events:
//   authentication failures, privilege changes, remote sessions,
//   non-routine process executions, and anything touching an external address.
// $routine_processes: everyday business applications to ignore.
MATCH (e:Event)
WHERE e.action IN ['logon_failure', 'privilege_change', 'rdp_session', 'smb_session']
   OR (e.action = 'process_execution'
       AND NOT EXISTS { (e)-[:EXECUTED]->(p:Process) WHERE p.name IN $routine_processes })
   OR EXISTS { (e)-[:INVOLVES]->(i:IP) WHERE NOT i.internal }
RETURN e.event_id AS event_id
ORDER BY event_id
