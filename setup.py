from setuptools import setup, find_packages

setup(
    name="arp-detection-system",
    version="1.0.0",
    description="Cross-platform ARP attack detection, validation, remediation, and isolation",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "paramiko>=3.4.0",
        "pywinrm>=0.5.0",
        "psutil>=5.9.0",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "pyyaml>=6.0",
        "jinja2>=3.1.0",
        "netaddr>=0.10.0",
        "cryptography>=42.0.0",
    ],
    entry_points={
        "console_scripts": [
            "arp-detect=arp_detection_system.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
