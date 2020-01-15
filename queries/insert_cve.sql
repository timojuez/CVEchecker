-- :name insert_cve :insert
INSERT INTO cve VALUES (:source, :cve_id, :cve_description, :base_metric, :impact_score, 
    :impact_severity, :publishedDate, :lastModifiedDate);
    

