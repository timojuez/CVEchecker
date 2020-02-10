-- :name get_cves_by_ids :many
SELECT *, strftime('%Y-%m-%d',lastModifiedDate) as lastModifiedDate_formatted, strftime('%Y-%m-%d',publishedDate) as publishedDate_formatted
FROM cve
WHERE cve_id IN :ids
ORDER BY impact_score DESC, lastModifiedDate DESC;

