-- :name get_cves :many
--SELECT packages.*, cve.*, strftime('%Y-%m-%d',lastModifiedDate) as lastModifiedDate_formatted, strftime('%Y-%m-%d',publishedDate) as publishedDate_formatted, printf("%.1f",impact_score) as impact_score_str
SELECT packages.product_name, packages.product_version, product.product_version as cve_product_version, product_version_affected as cve_product_version_affected, cve_id, printf("%.1f",impact_score) as impact_score, impact_severity, strftime('%Y-%m-%d',lastModifiedDate) as lastModifiedDate_formatted, strftime('%Y-%m-%d',publishedDate) as publishedDate_formatted, vector, impact_score_v2, cve_description, lastModifiedDate, publishedDate
FROM packages
LEFT JOIN product
ON lower(product.product_name) = lower(packages.product_name)
AND (
    product.product_version = packages.product_version
    OR product.product_version_affected != '='
)
LEFT JOIN cve
ON cve.rowid = product.cve
WHERE (cve_id IS NULL OR cve_id NOT IN :blacklist) 
AND (:fromDate IS NULL or publishedDate >= :fromDate)
ORDER BY lower(product.product_name) ASC, impact_score DESC, lastModifiedDate DESC;

