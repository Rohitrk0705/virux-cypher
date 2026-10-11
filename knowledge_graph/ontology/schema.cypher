// Virux Cypher knowledge graph schema: uniqueness constraints and indexes.
// Every statement is idempotent (IF NOT EXISTS). See ontology.md.

CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:Event) REQUIRE e.event_id IS UNIQUE;
CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT device_name IF NOT EXISTS FOR (d:Device) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;
CREATE CONSTRAINT process_name IF NOT EXISTS FOR (p:Process) REQUIRE p.name IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE;
CREATE CONSTRAINT tactic_name IF NOT EXISTS FOR (t:Tactic) REQUIRE t.name IS UNIQUE;
CREATE CONSTRAINT incident_uid IF NOT EXISTS FOR (i:Incident) REQUIRE i.uid IS UNIQUE;

CREATE INDEX event_ts IF NOT EXISTS FOR (e:Event) ON (e.ts);
CREATE INDEX event_action IF NOT EXISTS FOR (e:Event) ON (e.action);
CREATE INDEX incident_lookup IF NOT EXISTS FOR (i:Incident) ON (i.method, i.incident_id);
