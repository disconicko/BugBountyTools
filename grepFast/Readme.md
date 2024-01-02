# GrepFast - A Burp Suite Extension for Efficient Content Scanning

GrepFast is a powerful Jython Burp Suite extension designed to streamline the process of scanning web page responses for specific content using regular expressions. When a match is detected, GrepFast automatically generates an issue in the Burp Suite dashboard for further investigation. This extension also allows users to create, save, and toggle custom regular expressions to tailor the content discovery process according to their needs.

## Credits

It's important to note that GrepFast is inspired by the concept and name of Tomnomnom's GF tool for Burp Suite. While we take no credit for the original idea or name, we've endeavored to recreate an extension that performs similar functions within Burp Suite.

## Getting Started

To begin using GrepFast, follow these simple steps:

1. Clone the GrepFast repository to your local machine.
2. Open Burp Suite and navigate to the "Extensions" tab.
3. Click on "Add Extension" and import the `grepFast.py` file.
4. GrepFast is now integrated into your Burp Suite environment.

## Usage

GrepFast's primary function is to create issues in the Burp Suite dashboard whenever a regex match is identified within web page responses. Users can easily customize their regular expressions and enable or disable them as needed.

## Contributions

We welcome contributions from the community to enhance GrepFast further. If you have any ideas, suggestions, or improvements, please reach out to us or create a pull request. As this was our initial extension project, we believe there is ample room for improvement in various aspects of the codebase.

We hope GrepFast proves to be a valuable tool in your web security arsenal. Thank you for using our extension!

- TODO Fix Active button and save the current state to the json file. 
- TODO Fix name table so it doesn't get squashed when resized. 
- TODO add multiple regex's with + button.