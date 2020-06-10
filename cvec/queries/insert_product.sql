-- :name insert_product :insert
INSERT INTO product (cve,product_name,product_version,product_version_affected) VALUES (:cve, :product_name, :product_version, :product_version_affected);

