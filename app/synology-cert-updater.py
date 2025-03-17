import requests
import base64
from kubernetes import client, config  
from kubernetes.client import V1Secret
import re
import json
import functools
import logging
import sys
import os

# Kubernetes config
KUBECONFIG_MODE = os.getenv("KUBECONFIG_MODE")  # 'incluster' or 'local'

if KUBECONFIG_MODE == "incluster":
    config.load_incluster_config()  # If you are in a pod within kubernetes
else:
    config.load_kube_config()       # If you run locally for tests

# Synology config
SYNOLOGY_URL = os.getenv("SYNOLOGY_URL")
SYNOLOGY_USER = os.getenv("SYNOLOGY_USER")
SYNOLOGY_PASS = os.getenv("SYNOLOGY_PASS")
SECRET_NAME = os.getenv("SECRET_NAME")
SECRET_NAMESPACE = os.getenv("SECRET_NAMESPACE", "default")
COMMON_NAME = os.getenv("COMMON_NAME")

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
def log_exceptions(func):
    """
    Decorator to handle exceptions and add the function name to the log.
    :param func: Function on which the decorator is applied
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Get the name of the function that caused the error
            method_name = func.__name__
            # We register the error with the function name
            logging.error(f"Error in '{method_name}' function: {str(e)}")
            raise  # We rethrow the exception so that it can be handled further upstream if necessary
    return wrapper

@log_exceptions
def get_synology_sid(synology_url: str, synology_user: str, synology_pass: str) -> str | None:
    """
    Obtiene el token de sesión de Synology
    :param synology_url (str):      NAS URL
    :param synology_user (str):     User with administrative permissions on the NAS
    :param synology_pass (str):     NAS user password
    :return:                        Login session token
    """
    if not synology_url or not synology_user or not synology_pass:
        raise ValueError("The Synology credentials or URL are not correctly defined.")
    
    url = f"{synology_url}/webapi/auth.cgi"
    params = {
        "api": "SYNO.API.Auth",
        "version": "6",
        "method": "login",
        "account": synology_user,
        "passwd": synology_pass,
        "session": "FileStation",
        "format": "sid"
    }
    response = requests.get(url, params=params, verify=False)
    data = response.json()
    if data.get("success"):
        return data["data"]["sid"]
    else:
        logging.error(f"Error obtaining session token: {data}")
        return None

@log_exceptions
def get_secret_cert(secret_name: str, namespace: str = "default") -> dict:
    """
    Gets the certificate from the kubernetes secret in base64 format and processes it.
    :param secret_name:   Name of the secret containing the certificate
    :param namespace:     Namespace where the secret resides
    :return:              Returns the key, the certification chain and the certificate itself
    """

    if not secret_name:
        raise ValueError("The secretname must be defined.")
    # Obtaining the secret of the cert-manager certificate
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(secret_name, namespace)

    tls_key = base64.b64decode(secret.data["tls.key"]) # type: ignore
    tls_crt = base64.b64decode(secret.data["tls.crt"]) # type: ignore

    # Certificate processing
    cert_pattern = re.compile(rb'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', re.DOTALL)
    certs = cert_pattern.findall(tls_crt)

    # cert.crt contains the first certificate in bytes
    cert_crt = certs[0] if certs else b''

    # chain.crt contains the certificate chain
    chain_crt = b'\n'.join(certs[1:]) if len(certs) > 1 else b''

    # Return certificates in a dictionary
    return {
        "tls_key": tls_key,
        "cert_crt": cert_crt,
        "chain_crt": chain_crt
    }


@log_exceptions
def get_certificate_data(synology_url: str, common_name: str, session_id: str) -> dict | None:
    """
    Gets the certificate data in Synology given a common_name or sub_alt_name.
    :param synology_url:    NAS URL
    :param common_name:     Certificate Common name (CN)
    :param session_id:      NAS session token
    :return:                Dictionary with the ID and description of the certificate if found, None otherwise.
    """
    if not synology_url or not session_id or not common_name:
        raise ValueError("The synology_url, session_id or common_name parameters are not defined.")

    url = f"{synology_url}/webapi/entry.cgi"
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    cookies = {"id": session_id}
    data = {"api": "SYNO.Core.Certificate.CRT", "method": "list", "version": "1"}

    try:
        response = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)
        response.raise_for_status()
        certificates = response.json().get("data", {}).get("certificates", [])

        for cert in certificates:
            subject = cert.get("subject", {})
            common_name_cert = subject.get("common_name", "")
            sub_alt_names = subject.get("sub_alt_name", [])
            
            # Verify both common_name and sub_alt_name
            if common_name == common_name_cert or common_name in sub_alt_names:
                return {"id": cert.get("id"), "desc": cert.get("desc", "")}

        logging.info(f"No certificate with the Common Name or SAN found: '{common_name}'.")
        return None

    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP request error: {e}")
        raise
    except json.JSONDecodeError:
        logging.error("Error decoding JSON response.")
        raise
    except KeyError as e:
        logging.error(f"Error accessing response data: {e}")
        raise

@log_exceptions
def manage_synology_cert(cert_data: dict, cert_info: dict, session_id: str = ""):
    """
    Updates or creates a new certificate on Synology, depending on whether a cert_id is provided or not.

    :param cert_data:           Dictionary with the keys 'tls_key', 'cert_crt' and 'chain_crt'
    :param cert_info:           Dictionary with certificate data
    :param session_id (str):    Synology Session ID
    """
    # Verify that cert_info has 'id' and 'desc', otherwise empty values are assigned.
    cert_id = cert_info.get("id", "") if cert_info else ""
    description = cert_info.get("desc", "") if cert_info else ""

    try: 
        url = f"{SYNOLOGY_URL}/webapi/entry.cgi?api=SYNO.Core.Certificate&method=import&version=1&_sid={session_id}"
        files = {
            'key': ('tls.key', cert_data["tls_key"]),
            'cert': ('cert.crt', cert_data["cert_crt"]),
            'inter_cert': ('chain.crt', cert_data["chain_crt"])
        }
        data = {
            'id': cert_id,
            'desc': description,
            'as_default': ''
        }

        # Enviar la solicitud POST
        response = requests.post(url, files=files, data=data, verify=False)
        response.raise_for_status()

        logging.info(f"Certificate {'updated' if cert_id else 'created'} successfully.")
        return response

    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP request error: {e}")
        raise

# Only execute the script when explicitly invoked
if __name__ == "__main__":
    logging.info("Updating the certificate on Synology...")

    if SYNOLOGY_URL is None or SYNOLOGY_USER is None or SYNOLOGY_PASS is None:
        raise ValueError("SYNOLOGY_URL, SYNOLOGY_USER o SYNOLOGY_PASS must be defined.")
    sid = get_synology_sid(SYNOLOGY_URL,SYNOLOGY_USER,SYNOLOGY_PASS)
    #update_synology_cert()
    
    if SECRET_NAME is None or SECRET_NAMESPACE is None:
        raise ValueError("SECRET_NAME y SECRET_NAMESPACE must be defined.")
    
    cert_data = get_secret_cert(SECRET_NAME, SECRET_NAMESPACE)
    
    if sid is None or COMMON_NAME is None:
        raise ValueError("sid y COMMON_NAME  must be defined.")
    cert_info = get_certificate_data(SYNOLOGY_URL, COMMON_NAME, sid)
    logging.info(f"Certificado actual: {cert_info}")
    if cert_info is None:
            raise ValueError("cert_info  must be defined.")

    try:
        response = manage_synology_cert(cert_data, cert_info=cert_info, session_id=sid)
        if response is None:
            raise ValueError("No response was obtained in the certificate update")
        else:
            logging.info(f"Update Response: {response.text}")
    except Exception as e:
        logging.error(f"Error updating certificate: {str(e)}")
        raise  # Lanza el error para su manejo posterior