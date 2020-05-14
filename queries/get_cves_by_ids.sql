-- :name get_cves_by_ids :many
SELECT cve_id, printf("%.1f",impact_score) as impact_score, impact_severity, strftime('%Y-%m-%d',lastModifiedDate) as lastModifiedDate_formatted, strftime('%Y-%m-%d',publishedDate) as publishedDate_formatted, vector, impact_score_v2, cve_description, lastModifiedDate, publishedDate
FROM cve
WHERE cve_id IN :ids
ORDER BY impact_score DESC, lastModifiedDate DESC;

