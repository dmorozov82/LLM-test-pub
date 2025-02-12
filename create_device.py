import csv
import logging
import pynetbox
import requests
import sys
import time 
import ipaddress

# Configure logging
log_format = '%(asctime)s - %(levelname)s - %(filename)s - %(lineno)d - %(message)s'
logging.basicConfig(level=logging.DEBUG, format=log_format, filename='netbox_provision_sample.log') # Log to file
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler()) # Also output to console

requests.packages.urllib3.disable_warnings()  # Suppress SSL warnings

class NetBoxProvisioner:
    def __init__(self, nb_url, nb_token, csv_filepath, cert_path=None):
        logger.info(f"Initializing NetBoxProvisioner with URL: {nb_url}, CSV: {csv_filepath}, cert_path: {cert_path}")
        try:
            logger.info("Attempting to connect to NetBox...")
            self.nb = pynetbox.api(url=nb_url, token=nb_token)
            logger.info("Successfully connected to NetBox.")
            if cert_path:
                logger.info(f"Setting certificate path: {cert_path}")
                try:
                    self.nb.http_session.verify = cert_path  # Set certificate path here
                    logger.info("Certificate path set successfully.")
                except Exception as e:
                    logger.exception(f"Error setting certificate path: {e}")
                    sys.exit(1)
        except Exception as e:
            logger.exception(f"Error initializing pynetbox API: {e}")
            sys.exit(1)  # Exit if API initialization fails

        self.csv_filepath = csv_filepath

    def process_csv(self):
        logger.info(f"Processing CSV file: {self.csv_filepath}")
        try:
            with open(self.csv_filepath, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                if not reader:
                    logger.error("CSV file is empty or has no data rows.")
                    return

                for row_num, row in enumerate(reader, 1):
                    logger.info(f"Processing row {row_num}: {row}")
                    try:
                        self.create_tenant(row)
                        self.create_site(row)
                        self.create_device_type(row)
                        self.create_device(row) 
                    except Exception as e:
                        logger.exception(f"Error processing row {row_num}: {e}")
                        continue

        except FileNotFoundError:
            logger.error(f"CSV file '{self.csv_filepath}' not found.")
            sys.exit(1)
        except Exception as e:
            logger.exception(f"An unexpected error occurred during CSV processing: {e}")
            sys.exit(1)

    def create_tenant(self, row):
        tenant_name = row.get('tenant')
        logger.info(f"create_tenant called with tenant_name: {tenant_name}")
        if tenant_name is not None:
            try:
                tenant = self.nb.tenancy.tenants.get(name=tenant_name)
                if tenant:
                    logger.info(f"Tenant '{tenant_name}' already exists.")
                else:
                    logger.info(f"Creating tenant '{tenant_name}'")
                    # Corrected line: Add the slug field
                    tenant = self.nb.tenancy.tenants.create({'name': tenant_name, 'slug': tenant_name})
                    logger.info(f"Created tenant: {tenant_name}, tenant object: {tenant}")
            except pynetbox.core.query.RequestError as e:
                logger.exception(f"NetBox API RequestError creating or getting tenant '{tenant_name}': {e}")
            except requests.exceptions.RequestException as e:
                logger.exception(f"Network error creating or getting tenant '{tenant_name}': {e}")
            except AttributeError as e:
                logger.exception(f"AttributeError processing tenant '{tenant_name}': {e}")
                logger.error(f"Check if 'tenant' field exists in CSV row: {row}")
            except Exception as e:
                logger.exception(f"Unexpected error creating or getting tenant '{tenant_name}': {e}")

    def create_site(self, row):
        site_name = row.get('site')
        logger.info(f"create_site called with site_name: {site_name}")
        if site_name is not None:
            try:
                site = self.nb.dcim.sites.get(name=site_name)
                if site:
                    logger.info(f"Site '{site_name}' already exists.")
                else:
                    logger.info(f"Creating site '{site_name}'")
                    site = self.nb.dcim.sites.create({'name': site_name, 'slug': site_name}) # Added slug
                    logger.info(f"Created site: {site_name}, site object: {site}")
            except pynetbox.core.query.RequestError as e:
                logger.exception(f"NetBox API RequestError creating or getting site '{site_name}': {e}")
            except requests.exceptions.RequestException as e:
                logger.exception(f"Network error creating or getting site '{site_name}': {e}")
            except AttributeError as e:
                logger.exception(f"AttributeError processing site '{site_name}': {e}")
                logger.error(f"Check if 'site' field exists in CSV row: {row}")
            except Exception as e:
                logger.exception(f"Unexpected error creating or getting site '{site_name}': {e}")

    def create_device_type(self, row):
        device_type_slug = row.get('device_type').lower().replace(' ', '-')
        manufacturer_name = row.get('manufacturer')

        if device_type_slug and manufacturer_name:
            try:
                manufacturer_slug = manufacturer_name.lower().replace(' ', '-')
                manufacturer_name = row.get('manufacturer')
                manufacturer = self.nb.dcim.manufacturers.get(name=manufacturer_name, return_none=True)
                if not manufacturer:
                    # Generate a slug from the manufacturer name
                    manufacturer_slug = manufacturer_name.lower().replace(' ', '-')
                    manufacturer = self.nb.dcim.manufacturers.create({
                        'name': manufacturer_name,
                        'slug': manufacturer_slug  # Add the slug field
                    })
                    logger.info(f"Created manufacturer: {manufacturer_name}")
                else:
                    logger.info(f"Successfully retrieved manufacturer '{manufacturer_name}'")
            except Exception as e:
                logger.exception(f"Unexpected error creating device type '{device_type_name}': {e}")
                return None
            
            # Use ONLY the slug-based retrieval
            try:
                device_type = self.nb.dcim.device_types.get(slug=device_type_slug)
                logger.info(f"Device type '{device_type_slug}' already exists.")
                if not device_type:
                    device_type = self.nb.dcim.device_types.create({
                            'manufacturer': manufacturer.id,
                            'model': row.get('device_type'),
                            'slug': device_type_slug
                        })
                    logger.info(f"Created device type: {device_type_slug}, device type object: {device_type}")
                    return device_type
            except requests.exceptions.RequestException as e:
                logger.error(f"Network error creating device type '{device_type_slug}': {e}")
                return None
            except Exception as e:
                logger.exception(f"Unexpected error creating device type '{device_type_slug}': {e}")
                return None

    def _get_manufacturer_with_retry(self, manufacturer_slug, max_retries=5, retry_delay=2):
        for attempt in range(1, max_retries + 1):
            try:
                manufacturer = self.nb.dcim.manufacturers.get(slug=manufacturer_slug)
                return manufacturer
            except pynetbox.core.query.RequestError as e:
                if "Not Found" in str(e):
                    # Manufacturer doesn't exist yet, let's create it (this part remains the same)
                    manufacturer_name = manufacturer_slug.replace('-', ' ').title()
                    logger.info(f"Creating manufacturer '{manufacturer_name}' (attempt {attempt}/{max_retries})")
                    manufacturer = self.nb.dcim.manufacturers.create({
                        'name': manufacturer_name,
                        'slug': manufacturer_slug
                    })
                    logger.info(f"Created manufacturer: {manufacturer_name}, manufacturer object: {manufacturer}")
                    return manufacturer
                else:
                    if attempt == max_retries:
                        logger.error(f"Failed to retrieve manufacturer '{manufacturer_slug}' after {max_retries} retries: {e}")
                        return None
                    logger.warning(f"Error retrieving manufacturer '{manufacturer_slug}' (attempt {attempt}/{max_retries}): {e}. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff

    def create_device(self, row):
        device_name = row.get('device_name')
        site_name = row.get('site')
        manufacturer_name = row.get('manufacturer')
        device_type = row.get('device_type')
        primary_ip = row.get('primary_ip')

        logger.info(f"Processing device: {device_name}")

        try:
            site = self.nb.dcim.sites.get(name=site_name)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.error(f"Site '{site_name}' not found. Skipping device '{device_name}'.")
                return
            else:
                logger.exception(f"Error getting site '{site_name}': {e}")
                return
        except Exception as e:
            logger.exception(f"Unexpected error getting site '{site_name}': {e}")
            return

        try:
            manufacturer = self.get_manufacturer(manufacturer_name)
            if not manufacturer:
                logger.error(f"Manufacturer '{manufacturer_name}' not found. Skipping device '{device_name}'.")
                return

            device_role = self.get_device_role(row.get('device_role'))
            if not device_role:
                logger.error(f"Device role '{row.get('device_role')}' not found. Skipping device '{device_name}'.")
                return

            device = self.nb.dcim.devices.get(name=device_name, return_none=True)
            if device:
                logger.info(f"Device '{device_name}' already exists.")
                return
        
            if not self.validate_ip(primary_ip):
                logger.warning(f"Invalid IP address format: {primary_ip}. Skipping device creation.")
                return

            # Create IP address first
            ip_field = 'primary_ip4' if '.' in primary_ip else 'primary_ip6'
            ip_address_data = {'address': primary_ip, 'status': 'active'}

            tenant_name = row.get('tenant')
            if tenant_name:
                tenant = self.nb.tenancy.tenants.get(name=tenant_name, return_none=True)
                if tenant:
                    ip_address_data['tenant'] = tenant.id
                else:
                    logger.warning(f"Tenant '{tenant_name}' not found. Skipping tenant assignment for IP address '{primary_ip}'.")

            try:
                # Check if the IP address already exists
                existing_ip = self.nb.ipam.ip_addresses.get(address=primary_ip, return_none=True)
                if existing_ip:
                    logger.warning(f"IP address '{primary_ip}' already exists. Skipping creation.")
                    return None 

                ip_address = self.nb.ipam.ip_addresses.create(ip_address_data)
                logger.info(f"Created IP address: {primary_ip}")

            except Exception as e:
                logger.error(f"Error creating IP address '{primary_ip}': {e}")
                return
            
            # Create device with custom field and IP address
            device = self.nb.dcim.devices.create({
                'name': device_name,
                'device_type': device_type.id,
                'site': site.id,
                'status': row.get('status', 'active'),
                'device_role': device_role.id,
                'custom_fields': {
                    'role': row.get('role', 'compute'),
                    'state': row.get('state', 'ready')
                },
                ip_field: ip_address.id
            })
            logger.info(f"Created device: {device_name}, device object: {device}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error creating device '{device_name}': {e}")
        except Exception as e:
            logger.exception(f"Unexpected error creating device '{device_name}': {e}")

    ### Helper functions for better readability and error handling

    # Helper function to retrieve device type by name
    def get_device_type_by_name(self, device_type_name):
        try:
            device_type = self.nb.dcim.device_types.get(model=device_type_name)
            logger.info(f"Successfully retrieved device type '{device_type_name}': {device_type}") #Added success log
            return device_type
        except pynetbox.core.query.RequestError as e:
            logger.error(f"Error getting device type '{device_type_name}': {e}")
            return None
        
    # Helper function to retrieve device type by name and manufacturer
    def get_device_type(self, manufacturer, device_type_name):
        try:
            device_type = self.nb.dcim.device_types.get(manufacturer=manufacturer.id, model=device_type_name)
            logger.info(f"Successfully retrieved device type '{device_type_name}': {device_type}") #Added success log
            return device_type
        except pynetbox.core.query.RequestError as e:
            logger.error(f"Error getting device type '{device_type_name}': {e}")
            return None
        
    # Helper function to retrieve manufacturer by name
    def get_manufacturer(self, manufacturer_name):
        try:
            manufacturer = self.nb.dcim.manufacturers.get(name=manufacturer_name)
            logger.info(f"Successfully retrieved manufacturer '{manufacturer_name}': {manufacturer}") #Added success log
            return manufacturer
        except pynetbox.core.query.RequestError as e:
            logger.error(f"Error getting manufacturer '{manufacturer_name}': {e}")
            return None

    # Helper function to retrieve custom field choice ID
    def get_custom_field_choice_id(self, field_name, choice_value):
        try:
            custom_field = self.nb.extras.customfields.get(name=field_name)
            for choice in custom_field.choices:
                if choice['value'] == choice_value:
                    logger.info(f"Successfully retrieved custom field choice ID for '{field_name}' with value '{choice_value}': {choice['id']}") #Added success log
                    return choice['id']
            return None
        except Exception as e:
            logger.error(f"Error getting custom field choice ID: {e}")
            return None

    # Helper function to retrieve site by name
    def get_site(self, site_name):
        try:
            site = self.nb.dcim.sites.get(name=site_name)
            logger.info(f"Successfully retrieved site '{site_name}': {site}") #Added success log
            return site
        except pynetbox.core.query.RequestError as e:
            logger.error(f"Error getting site '{site_name}': {e}")
            return None
        
    # Helper function to retrieve device role by name
    def get_device_role(self, device_role_name):
        try:
            device_role = self.nb.dcim.device_roles.get(name=device_role_name)
            logger.info(f"Successfully retrieved device role '{device_role_name}': {device_role}") #Added success log
            return device_role
        except pynetbox.core.query.RequestError as e:
            logger.error(f"Error getting device role '{device_role_name}': {e}")
            return None
        
    # Helper function to validate IP address
    def validate_ip(self, ip_address):
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

# --- Configuration ---
NETBOX_URL = "https://netbox.sales-lab.demo.lab.itkey.com"
NETBOX_TOKEN = "9f1419755317d1c1cf151890505bbd3210929add"
CSV_FILEPATH = "/home/ubuntu/data.csv"

cert_file = "/installer/data/ca/cert/chain-ca.pem"

provisioner = NetBoxProvisioner(NETBOX_URL, NETBOX_TOKEN, CSV_FILEPATH, cert_file)
provisioner.process_csv()
