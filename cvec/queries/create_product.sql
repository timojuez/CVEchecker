-- :name create_product
CREATE TABLE product (
    cve INT REFERENCES cve,
    product_name TEXT,
    product_version TEXT
);


