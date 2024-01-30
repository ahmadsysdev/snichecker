# !/usr/bin/env python
import urllib.parse
import re
import xray2json
import json
import os
import uuid
import random
import subprocess
import signal
import requests
import time
import logging
import threading
import copy
import datetime
import sys
import argparse

# Create temp directory
if not os.path.exists('tmp'):
    os.makedirs('tmp')

# Global variable
ports = random.sample(range(1024, 65536), 100)

# Configuring logging module with a specific format and log level.
PREFIX = '\033['
SUFFIX = '\033[0m'
MAPPING = {
    'DEBUG': 37,
    'INFO': 36,
    'WARNING': 33,
    'ERROR': 31,
    'CRITICAL': 41,
    'TIME': 32
}

# Log formatter
class LogFormatter(logging.Formatter):
    def format(self, record):
        # Customize the log record's formatting by adding ANSI color codes for log level.
        colored_record = copy.copy(record)
        levelname = colored_record.levelname
        seq = MAPPING.get(levelname, 37)
        colored_record.levelname = ('{0}{1}m{2}{3}'.format(PREFIX, seq, levelname, SUFFIX))
        return logging.Formatter.format(self, colored_record)
    def formatTime(self, record, datefmt=None):
        # Customize the time format.
        seq = MAPPING.get('TIME', 37)
        converter = datetime.datetime.fromtimestamp(record.created)
        if datefmt:
            t = converter.strftime(datefmt)
            s = '{0}{1}m{2}{3}'.format(PREFIX, seq, t, SUFFIX)
        else:
            t = converter.strftime('%Y-%m-%d %H:%M:%S')
            f = '%s,%03d' % (t, record.msecs)
            s = '{0}{1}m{2}{3}'.format(PREFIX, seq, f, SUFFIX)
        return s

# Create a console handler for displaying log on the console.
ch = logging.StreamHandler()
logger = logging.getLogger(__name__)

# Create a custom formatter with desired time format.
formatter = LogFormatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.setLevel(logging.INFO)

def parse_config(config: str) -> dict:
    """
    Parse a configuration string and return a dictionary with key-value pairs.

    Parameters:
    - config (str): The configuration string.

    Returns:
    - dict: A dictionary containing parsed key-value pairs.

    Raises:
    - ValueError: If the configuration string is not in the expected format.
    - ValueError: If the port cannot be converted to an integer.
    """

    result = {}

    try:
        # Parse the URL
        parse = urllib.parse.urlparse(config)

        # Ensure the URL has the expected structure
        if not parse.scheme or not parse.netloc:
            raise ValueError("Invalid configuration string. Missing scheme or netloc.")

        # Extract basic information
        result['proto'] = parse.scheme
        result['uuid'] = parse.netloc.split('@')[0]
        result['address'] = parse.netloc.split('@')[1].split(':')[0]

        # Parse and handle port as an integer
        try:
            result['port'] = int(parse.netloc.split(':')[1])
        except (IndexError, ValueError):
            raise ValueError("Invalid or missing port in the configuration string.")

        # Parse the queries
        qs = {key: value[0] for key, value in urllib.parse.parse_qs(parse.query).items()}
        result.update(qs)

    except Exception as e:
        raise ValueError(f"Error parsing configuration string: {str(e)}")

    return result

def replace_nth(string: str, __old: str, __new: str, n: int) -> str:
    """
    Replace the nth occurrence of a substring in a string.

    Parameters:
    - string (str): The original string.
    - __old (str): The substring to be replaced.
    - __new (str): The replacement substring.
    - n (int): The occurrence number to be replaced.

    Returns:
    - str: The updated string after replacing the nth occurrence.

    Note:
    - If n is invalid (less than or equal to 0, or greater than the number of occurrences), 
      the original string is returned without any modifications.
    """
    # Find all occurrences of the substring in the string
    occurrences = [m.start() for m in re.finditer(re.escape(__old), string)]

    if n <= 0 or n > len(occurrences):
        # Invalid n, do nothing
        return string

    # Find the index of the nth occurrence
    nth_occurrence_index = occurrences[n-1]

    # Split the string into prefix and suffix at the nth occurrence
    prefix = string[:nth_occurrence_index]
    suffix = string[nth_occurrence_index:]

    # Replace the substring in the suffix
    updated_suffix = suffix.replace(__old, __new, 1)

    # Combine the prefix and the updated suffix
    return prefix + updated_suffix

class SniChecker:
    def __init__(self, sni: str, config: str) -> None:
        """
        Initialize the SniChecker instance.

        Args:
            sni (str): The Server Name Indication (SNI) to be used for generating URLs.
            config (str): The configuration string containing the base URL and additional settings.
        """
        # Store the provided SNI and URL configuration in instance attributes
        self.sni = sni
        self.url = config

        # Parse the configuration string and store the result in self.config
        self.config = parse_config(config)

        # Initialize an empty list to store generated URLs
        self.urls = []

    def generate(self):
        """
        Generate a list of URLs based on the provided SNI and configuration.

        Returns:
            list: A list of generated URLs.
        """
        address = self.config['address']
        url = self.url
        generated_urls = []

        generated_urls.append(url.replace(address, self.sni, 1))
        # return generated_urls

        if self.config.get('sni'):
            # Generate URLs with the SNI replaced at different occurrences
            generated_urls.append(replace_nth(url, address, self.sni, 2))

        if self.config.get('host'):
            # Generate URL with the SNI replaced at the 3rd occurrence
            generated_urls.append(replace_nth(url, address, self.sni, len(generated_urls)+1))
        
        if len(generated_urls) != 1:
            for i in range(len(generated_urls)):
                if i == 0:
                    continue
                url = generated_urls[i]
                for j in range(url.count(address)-1):
                    generated_urls.append(replace_nth(url, address, self.sni, j+1))
        # return list(set(generated_urls))
        return generated_urls
    
    def run(self, urls) -> str:
        """
        Execute the XRay tool with the provided URLs.

        Parameters:
        - urls (list): List of URLs to be processed by XRay.

        Returns:
        - result: Returns the input 'urls' if the XRay execution is successful,
                  otherwise returns False.

        Note:
        - XRay configuration is generated dynamically using the 'xray2json.generateConfig' method.
        - XRay is executed as a subprocess, and a temporary configuration file is created.
        - A request is made using a proxy configured with the generated port.
        - The XRay process is terminated, and the temporary configuration file is removed.
        """

        # Get a port from the available ports
        port = ports.pop()

        # Generate XRay config JSON and replace the port
        config = json.loads(xray2json.generateConfig(urls).replace('1080', str(port)))

        # Create a unique filename for the XRay configuration
        filename = 'tmp/{}.json'.format(uuid.uuid4())

        # Write the XRay configuration to a file
        file = open(filename, 'w')
        json.dump(config, file, indent=4)
        file.close()

        # Run XRay as a subprocess using the generated configuration file
        process = subprocess.Popen('xray run -c "{}"'.format(filename), shell=True, preexec_fn=os.setsid, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        result = None

        try:
            # Sleep to allow XRay to start
            time.sleep(1)

            # Make a request using the configured proxy
            requests.get('https://api.ipify.org', proxies=dict(http='socks5://127.0.0.1:{}'.format(port), https='socks5://127.0.0.1:{}'.format(port)), timeout=7)

            # If the request is successful, set result to the input 'urls'
            result = urls
            logger.info('Vulnerable: {}'.format(urls))
        except Exception as e:
            # Log the exception (consider using a logging library instead of print)
            logger.warning('Failed to establish connection at port {} (Not vulnerable)'.format(port))

            # If an exception occurs, set result to False
            result = False
        finally:
            # Terminate the XRay process and wait for it to finish
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait()

            # Close the file and remove the temporary configuration file
            file.close()
            os.remove(filename)

        # Return the result
        return result


def start(config: str, sni: str = 'bug.txt'):
    """
    Start the SniChecker with the provided configuration and SNI file.

    Parameters:
    - config (str): XRay config.
    - sni (str): Path to the file containing SNI (Server Name Indication) values.

    Note:
    - The 'SniChecker' class is used to perform SNI checks based on the provided configuration and SNI values.
    - The 'generate' method of 'SniChecker' is called to generate URLs based on the specified SNI values and configuration.

    Example:
    ```
    start('vless://uuid@0.0.0.0:80?host=0.0.0.0', '/path/to/sni.txt')
    ```
    """

    # Read SNI values from the specified file
    configs = []
    sni = [x.decode('utf-8').strip() for x in open(sni, 'rb')]

    for x in sni:
        # Instantiate SniChecker with a specific SNI and URL configuration
        sni_checker = SniChecker(
            sni=x,
            config=config
        )

        # Generate URLs based on the SNI values and configuration
        generated_urls = sni_checker.generate()
        configs.extend(generated_urls)
    
    # Creating threading.Semaphore to control the number of concurrent threads
    max_threads = 10
    semaphore = threading.Semaphore(value=max_threads)
    
    # Start threads
    threads = []
    for config in configs:
        thread = threading.Thread(target=lambda x=config: sni_checker.run(x))
        threads.append(thread)
        thread.start()
    for x in threads:
        try:
            x.join()
        except Exception as e:
            logger.critical(e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SNI Checker using XRay Core Config")
    parser.add_argument("-c", "--config", type=str, required=True, help="Path to XRay Core config file")
    parser.add_argument("-f", "--sni", type=str, help="Path to the file containing SNI values")
    args = parser.parse_args()
    start(args.config)