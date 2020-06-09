import setuptools, os

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cvec",
    version="0.1.0",
    author="Timo Richter",
    author_email="",
    description="CVE checker - Find CVEs that affect given program(s)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/timojuez/CVEchecker",
    install_requires=["cvss","cvsslib","zipp","requests","pugsql"],
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    scripts=["bin/%s"%f for f in os.listdir("bin")],
    python_requires='>=3.6',
    include_package_data=True,
)

