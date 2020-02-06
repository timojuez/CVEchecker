-- :name insert_cve :insert
INSERT INTO cve VALUES (:source, :cve_id, :cve_description, :impact_score, 
    :impact_severity, :publishedDate, :lastModifiedDate, :vector, :impact_score_v2);
    

