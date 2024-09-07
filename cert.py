import requests
import logging
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509 import CertificateSigningRequestBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
from typing import List, Tuple, Dict


class SSLCertificateManager:
    """
    A class to manage SSL certificate generation and signing.

    Attributes:
        hosts (List[str]): List of hostnames for which to generate certificates.
        country (str): Country name for the certificate.
        state (str): State or province name for the certificate.
        city (str): Locality name for the certificate.
        organization (str): Organization name for the certificate.
        organizational_unit (str): Organizational unit name for the certificate.
        email (str): Email address for the certificate.
        api_key (str): API key for the SSL API.
        ca_api_url (str): Base URL for the SSL API.
        output_directory (str): Directory to save the generated keys and CSRs.
    """

    def __init__(self, hosts: List[str], country: str, state: str, city: str, organization: str, organizational_unit: str, email: str) -> None:
        """
        Initializes the SSLCertificateManager with the given parameters.

        Args:
            hosts (List[str]): List of hostnames for which to generate certificates.
            country (str): Country name for the certificate.
            state (str): State or province name for the certificate.
            city (str): Locality name for the certificate.
            organization (str): Organization name for the certificate.
            organizational_unit (str): Organizational unit name for the certificate.
            email (str): Email address for the certificate.
        """
        self.hosts: List[str] = list(set(hosts))  # Remove duplicates
        self.country: str = country
        self.state: str = state
        self.city: str = city
        self.organization: str = organization
        self.organizational_unit: str = organizational_unit
        self.email: str = email
        self.api_key: str = os.environ["SSL_API_KEY"]
        self.ca_api_url: str = "https://sslapi.cryptosvcs.cisco.com/sslapi"
        logging.basicConfig(level=logging.INFO)  # Set up logging

        # Set up the output directory on the Desktop
        self.output_directory: str = "keys"
        logging.info(f"Attempting to create directory at: {self.output_directory}")

        try:
            os.makedirs(self.output_directory, exist_ok=True)  # Create the folder if it doesn't exist
            logging.info(f"Output directory successfully created at: {self.output_directory}")
        except Exception as e:
            logging.error(f"Failed to create output directory: {e}")
            raise

    def sign_csr(self, csr_base64: str) -> None:
        """
        Signs a Certificate Signing Request (CSR) using the SSL API.

        Args:
            csr_base64 (str): The CSR in base64 encoded format.

        Raises:
            HTTPError: If an HTTP error occurs during the request.
            Exception: If any other error occurs.
        """
        url: str = f"{self.ca_api_url}/v1/sign/csr"

        payload: Dict[str, str] = {
            "csr": csr_base64,
            "validity_period": "one_year"
        }
        headers: Dict[str, str] = {
            "Authorization": f'SSLAPI api_key="{self.api_key}"',
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            response: requests.Response = requests.post(url, data=payload, headers=headers)
            logging.debug(f"CSR sign URL: {response.request.url}")
            logging.debug(f"CSR sign headers: {response.request.headers}")
            logging.debug(f"CSR sign payload: {payload}")  # Ensure payload is correctly formatted
            logging.debug(f"CSR sign response status code: {response.status_code}")
            logging.debug(f"CSR sign response text: {response.text}")

            response.raise_for_status()
            logging.info("CSR signed successfully.")
            return
        except requests.exceptions.HTTPError as http_err:
            logging.error(f"HTTP error occurred: {http_err}")
            raise
        except Exception as e:
            logging.error(f"Other error occurred: {e}")
            raise

    def get_issuer_info(self) -> None:
        """
        Retrieves issuer information from the SSL API and saves it to a file.

        Raises:
            HTTPError: If an HTTP error occurs during the request.
            Exception: If any other error occurs.
        """
        url: str = f"{self.ca_api_url}/v1/cert/issuer"

        headers: Dict[str, str] = {
            "Authorization": f'SSLAPI api_key="{self.api_key}"'
        }

        try:
            response: requests.Response = requests.get(url, headers=headers)
            root_cert: str = response.text

            response.raise_for_status()
            logging.info("Issuer information retrieved successfully.")

            root_file_path: str = os.path.join(self.output_directory, "telegraf_root.pem")
            with open(root_file_path, 'wb') as key_file:
                key_file.write(root_cert.encode('utf-8'))

            return
        except requests.exceptions.HTTPError as http_err:
            logging.error(f"HTTP error occurred: {http_err}")
            raise
        except Exception as e:
            logging.error(f"Other error occurred: {e}")
            raise

    def process_hosts(self) -> None:
        """
        Processes each host in the list to generate keys, CSRs, and sign the CSRs.
        """
        for host in self.hosts:
            logging.info(f"Processing {host}...")
            try:
                private_key_pem, csr_pem = self.generate_key_and_csr(host)
                self.sign_csr(csr_pem.decode('utf-8'))
                
                logging.info(f"Completed processing for {host}.")
            except Exception as e:
                logging.error(f"Failed to process {host}: {e}")

    def generate_key_and_csr(self, host: str) -> Tuple[bytes, bytes]:
        """
        Generates a private key and a Certificate Signing Request (CSR) for a given host.

        Args:
            host (str): The hostname for which to generate the key and CSR.

        Returns:
            Tuple[bytes, bytes]: The private key and CSR in PEM format.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private_key_pem: bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )

        csr_builder = CertificateSigningRequestBuilder().subject_name(
            Name([
                NameAttribute(NameOID.COUNTRY_NAME, self.country),
                NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state),
                NameAttribute(NameOID.LOCALITY_NAME, self.city),
                NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
                NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit),
                NameAttribute(NameOID.COMMON_NAME, host),
                NameAttribute(NameOID.EMAIL_ADDRESS, self.email),
            ])
        )
        csr = csr_builder.sign(private_key, hashes.SHA256())
        csr_pem: bytes = csr.public_bytes(serialization.Encoding.PEM)

        key_file_path: str = os.path.join(self.output_directory, f"{host}_key.pem")
        csr_file_path: str = os.path.join(self.output_directory, f"{host}_csr.pem")

        with open(key_file_path, 'wb') as key_file:
            key_file.write(private_key_pem)

        with open(csr_file_path, 'wb') as csr_file:
            csr_file.write(csr_pem)

        return private_key_pem, csr_pem


def main() -> None:
    """
    Main function to initialize the SSLCertificateManager and process the hosts.
    """
    hosts: List[str] = [
        'neo-influxdb-dev04.cisco.com', 'neo-telegraf-dev01.cisco.com', 'neo-telegraf-dev02.cisco.com',
        'neo-telegraf-dev03.cisco.com', 'neo-telegraf-dev04.cisco.com',
        'neo-telegraf-dev05.cisco.com', 'neo-telegraf-dev01-dmz.cisco.com',
        'neo-telegraf-prod01.cisco.com', 'neo-telegraf-prod03.cisco.com',
        'neo-telegraf-prod05.cisco.com', 'neo-telegraf-prod06.cisco.com',
        'neo-telegraf-prod07.cisco.com', 'neo-telegraf-prod08.cisco.com',
        'neo-telegraf-prod09.cisco.com', 'neo-telegraf-prod10.cisco.com',
        'neo-telegraf-prod11.cisco.com', 'neo-telegraf-prod12.cisco.com',
        'neo-telegraf-prod13.cisco.com', 'neo-telegraf-prod14.cisco.com',
        'neo-telegraf-prod15.cisco.com', 'neo-telegraf-prod16.cisco.com',
        'neo-telegraf-prod17.cisco.com', 'neo-telegraf-prod19.cisco.com',
        'neo-telegraf-prod20.cisco.com', 'neo-telegraf-prod21.cisco.com',
        'neo-telegraf-prod22.cisco.com', 'neo-telegraf-prod23.cisco.com'
    ]

    country: str = "US"
    state: str = "California"
    city: str = "San Jose"
    organization: str = "Cisco Systems Inc"
    organizational_unit: str = "IT"
    email: str = "neo-observability@cisco.com"

    cert_manager: SSLCertificateManager = SSLCertificateManager(
        hosts, country, state, city, organization, organizational_unit, email
    )
    cert_manager.process_hosts()
    cert_manager.get_issuer_info()


if __name__ == "__main__":
    main()
