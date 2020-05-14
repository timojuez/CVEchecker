-- :name create_cve
CREATE TABLE cve (
    --id PRIMARY KEY,
    source INT REFERENCES source,
    cve_id TEXT,
    cve_description TEXT,
    impact_score DECIMAL(3,1),
    impact_severity TEXT,
    publishedDate datetime,
    lastModifiedDate datetime,
    vector TEXT,
    impact_score_v2 DECIMAL(3,1) DEFAULT NULL
);
