# SNI Checker

## What is this for

This is a Python script designed to validate and test network configurations for bypassing restrictions using Xray Core. It focuses on checking the Server Name Indication (SNI) functionality in scenarios such as an expired SIM card, absence of a subscription, and more. The tool aims to ensure reliable bypassing capabilities in diverse network conditions.

## Requirements

- [Xray Core](https://github.com/XTLS/Xray-core): The underlying technology for the SNI Checker.
- Python: The scripting language used for the project.

## Installation

1. ***Install Xray Core:***
    Follow the instructions on [Xray Install](https://github.com/XTLS/Xray-install) to install Xray Core on your system.

2. **Install Python:**
   Make sure Python is installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

## Usage

Run the following command in your terminal:

1. Install the requirements:
    ```bash
    pip install -r requirements.txt
    ```
2. Run the script:
    ```bash
    python main.py -c "vless://0b883ea5-387c-4b10-a068-b98935697e74@test.com:80?host=test.com&path=/vless&type=ws&encryption=none#YourMom"
    ```

Replace the config with your actual raw configuration. The configuration supports any protocol related to Xray Core, such as vless, vmess, shadowsocks, trojan, etc.

## Notes

- Ensure you have the list of bug hosts in the `bug.txt` file.

- It is recommended to test the script with various scenarios, such as using an expired SIM card, to ensure its functionality in different conditions.

- Consider testing the SNI Checker in various scenarios to ensure robust performance. The scenarios you choose are entirely open-ended and depend on your creativity.

## Additional Information

- For Windows Users:
If you are using Windows, additional steps or modifications may be required. Please adapt the provided instructions accordingly.

## Support and Contact

If you encounter any issues or have questions, feel free to reach out [via Telegram](https://t.me/ahmadsysdev).