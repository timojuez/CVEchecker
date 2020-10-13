-- :name get_cves :many
SELECT cve_id, printf("%.1f",impact_score) as impact_score, impact_severity, strftime('%Y-%m-%d',lastModifiedDate) as lastModifiedDate_formatted, strftime('%Y-%m-%d',publishedDate) as publishedDate_formatted, vector, impact_score_v2, cve_description, lastModifiedDate, publishedDate, configuration
FROM cve;

