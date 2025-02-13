import csv
import logging
import pynetbox # type: ignore
import requests
import os 
import sys
import time 
import ipaddress
import json


# Configure logging
log_format = '%(asctime)s - %(levelname)s - %(filename)s - %(lineno)d - %(message)s'
logging.basicConfig(level=logging.DEBUG, format=log_format, filename='custom_fields.log') # Log to file
logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler()) # Also output to console

requests.packages.urllib3.disable_warnings()  # Suppress SSL warnings

NETBOX_URL = os.environ.get('NETBOX_URL', 'https://netbox.lab..com')
NETBOX_TOKEN = os.environ.get('NETBOX_TOKEN', '9f1419755317d05bbd3210929add')

# CSV_FILEPATH = "/home/ubuntu/data.csv"
cert_file = "/installer/data/ca/cert/chain-ca.pem"

def get_custom_field_choice_id(nb, choice_set_name, choice_value):
    try:
        # Get custom field ID first
        url = f"{NETBOX_URL}/api/extras/custom-fields/?name={choice_set_name}"
        headers = {'Authorization': f'Token {NETBOX_TOKEN}', 'Accept': 'application/json'}
        response = requests.get(url, headers=headers, verify=False) # verify=False - INSECURE - ONLY FOR TESTING
        response.raise_for_status()
        data = response.json()

        if data['count'] == 0:
            logger.error(f"Custom field '{choice_set_name}' not found.")
            return None

        custom_field_id = data['results'][0]['id']

        # Get choices for the custom field
        choices_url = f"{NETBOX_URL}/api/extras/custom-field-choices/?custom_field={custom_field_id}"
        choices_response = requests.get(choices_url, headers=headers, verify=False) # verify=False - INSECURE - ONLY FOR TESTING
        choices_response.raise_for_status()
        choices_data = choices_response.json()

        for choice in choices_data['results']:
            if choice['value'] == choice_value:
                return choice['id']

        logger.error(f"Custom field choice '{choice_value}' not found in choice set '{choice_set_name}'.")
        return None

    except requests.exceptions.RequestException as e:
        logger.exception(f"Error fetching custom field choice '{choice_value}' from choice set '{choice_set_name}': {e}")
        return None
    except (KeyError, IndexError) as e:
        logger.exception(f"Error parsing API response: {e}")
        return None


def get_custom_field_data(nb, row):
    custom_fields = {}
    try:
        url = f"{NETBOX_URL}/api/extras/custom-fields/"
        headers = {'Authorization': f'Token {NETBOX_TOKEN}', 'Accept': 'application/json'}
        response = requests.get(url, headers=headers, verify=False) # verify=False - INSECURE - ONLY FOR TESTING
        response.raise_for_status()
        custom_fields_data = response.json()['results']

        custom_field_map = {cf['name']: cf for cf in custom_fields_data}

        for field_name, field_value in row.items():
            if field_name in custom_field_map:
                custom_field = custom_field_map[field_name]
                choice_set_id = custom_field['choice_set']['id']
                
                # Fetch choice set data only if needed
                if custom_field['type']['value'] in ('select', 'multiselect'):
                    choice_set_url = custom_field['choice_set']['url']
                    choice_set_response = requests.get(choice_set_url, headers=headers, verify=False) # verify=False - INSECURE - ONLY FOR TESTING
                    choice_set_response.raise_for_status()
                    choice_set_data = choice_set_response.json()

                    for choice in choice_set_data['extra_choices']:
                        if choice[1] == field_value:
                            custom_fields[field_name] = choice_set_id
                            break
                    else:
                        logger.warning(f"Choice '{field_value}' not found for field '{field_name}'.")
                else:
                    custom_fields[field_name] = field_value # Handle non-choice fields

        return custom_fields

    except requests.exceptions.RequestException as e:
        logger.exception(f"Error fetching custom field data: {e}")
        return None
    except (KeyError, IndexError) as e:
        logger.exception(f"Error parsing API response: {e}")
        return None


if __name__ == "__main__":
    try:
        # Connect to NetBox API
        nb = pynetbox.api(url=NETBOX_URL, token=NETBOX_TOKEN)

        # Sample data (replace with your data)
        sample_data = {'role': 'compute', 'state': 'ready'}

        # Get custom field data
        custom_fields_data = get_custom_field_data(nb, sample_data)
        print(f"Custom field data: {custom_fields_data}") # This line was missing

    except Exception as e:
        logger.exception(f"An error occurred: {e}")
