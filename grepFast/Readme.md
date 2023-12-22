# GrepFast

GrepFast is a Jython Burpsuite extension that scans all responses from webpages and searches the content matching regular expressions. Whenever a match is found, the extension will create an issue in the dashboard for investigation. Custom regular expressions can be created, saved, and turned on/off depending on the content you are trying to discover. I take no credit for the Grep Fast idea or name, I just wanted to re-create an extension to do what Tomnomnom's GF tool does in Burpsuite. 

# How to use:
To use GrepFast clone the repository locally. Open up Burpsuite and go to the extensions tab. Click "Add Extension" and import grepFast.py. 
For all ideas to uplift this tool please reach out or create a push request. This was my first extension and I am sure my code can be uplifted in many areas. 
I hope everyone finds this tool useful.

- TODO Fix name table so it doesn't get squashed when resized. 
- TODO Fix config save. Newly saved regex do not update the nameTable list. They are successfully added to the config and will create alerts. However, the change is not updated in the GUI.
- TODO add multiple regex's with + button.