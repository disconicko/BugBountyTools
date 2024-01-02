from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IHttpRequestResponseWithMarkers
from java.awt import GridBagLayout, GridBagConstraints, Component, Dimension, Font, Color, FlowLayout, BorderLayout
from java.awt.event import ActionListener, ActionEvent, MouseAdapter
from javax.swing import JTable, JScrollPane, BorderFactory, JList, JPanel, BoxLayout, JScrollPane, JCheckBox, JButton, DefaultListModel, DefaultListCellRenderer, JTextField, JComboBox, JLabel, JTextArea
from javax.swing.table import DefaultTableModel
from java.util import ArrayList
import json
import re
from array import array

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def __init__(self):
        self.regexJson = self.loadRegexFile()
        self.panel = self.getUiComponent()

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.setExtensionName("Grep Fast")

    def getTabCaption(self):
        return "Grep Fast"

    def getUiComponent(self):
        # Initialize GridBagLayout and GridBagConstraints
        mainPanel = JPanel(GridBagLayout())
        c = GridBagConstraints()

        #default Borders for panels:
        borderPadding = BorderFactory.createEmptyBorder(5, 5, 5, 5)
        borderOutline = BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1)
        compoundBorder = BorderFactory.createCompoundBorder(borderPadding, borderOutline)

        # Title label at the top
        titleLabel = JLabel("Grep Fast")
        titleLabel.setFont(Font("Arial", Font.BOLD, 24))
        titleLabel.setForeground(Color(255, 102, 0))
        titleLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        titlePanel = JPanel()
        titlePanel.add(titleLabel)
        c.gridx = 0
        c.gridy = 0
        c.gridwidth = 9
        c.gridheight = 1
        c.weightx = 1.0
        c.weighty = 0.0
        c.fill = GridBagConstraints.HORIZONTAL
        mainPanel.add(titlePanel, c)

        # Left panel for names
        nameListPanel = JScrollPane(self.createNameList())
        nameListPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        nameListPanel.setMinimumSize(Dimension(300,800))
        c.gridx = 0
        c.gridy = 1
        c.gridwidth = 3
        c.gridheight = 8
        c.fill = GridBagConstraints.BOTH
        c.weightx = 1.0
        c.weighty = 0.0
        mainPanel.add(nameListPanel, c)

        # Middle-Top panel for checkbox and description
        self.descriptionArea = JTextArea()
        self.descriptionArea.setLineWrap(False)
        self.descriptionArea.setEditable(False)
        descriptionScrollPane = JScrollPane(self.descriptionArea, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        descriptionScrollPane.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1))
        self.checkbox = JCheckBox("Active")

        # Middle-Top panel for checkbox and description
        descriptionContainerPanel = JPanel(BorderLayout())
        descriptionContainerPanel.add(descriptionScrollPane, BorderLayout.CENTER)
        descriptionContainerPanel.add(self.checkbox, BorderLayout.SOUTH)
        c.gridx = 3
        c.gridy = 1
        c.gridwidth = 4
        c.gridheight = 3
        c.weightx = 0.5
        c.weighty = 0.5
        descriptionContainerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        mainPanel.add(descriptionContainerPanel, c)

        # Empty panel for spacing on the right
        emptyPanelRight = JPanel()
        emptyPanelRight.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        c.gridx = 7
        c.gridy = 1
        c.gridwidth = 2
        c.gridheight = 8
        c.weightx = 0.5
        c.weighty= 0.5
        c.fill = GridBagConstraints.BOTH
        mainPanel.add(emptyPanelRight, c)

        # Middle-Bottom panel for regex configuration
        configPanel = self.createConfigPanel()
        configPanel.setBorder(compoundBorder)
        c.gridx = 3
        c.gridy = 4
        c.gridwidth = 3
        c.gridheight = 2
        c.fill = GridBagConstraints.BOTH
        c.weightx = 0.5
        c.weighty = 0.5
        configPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        mainPanel.add(configPanel, c)

        # Empty panel for spacing on the bottom
        emptyPanelBottom = JPanel()
        emptyPanelBottom.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        c.gridx = 3
        c.gridy = 6
        c.gridwidth = 3
        c.gridheight = 1
        c.weightx = 0.0
        c.weighty = 0.0
        c.fill = GridBagConstraints.HORIZONTAL
        mainPanel.add(emptyPanelBottom, c)

        return mainPanel

    #Panel for saving Regex to the config
    def createConfigPanel(self):
        configPanel = JPanel()
        configPanel.setLayout(BoxLayout(configPanel, BoxLayout.Y_AXIS))

        #default Borders for config items
        borderPadding = BorderFactory.createEmptyBorder(10, 10, 10, 10)
        borderOutline = BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1)
        compoundBorder = BorderFactory.createCompoundBorder(borderOutline, borderPadding)

        # Save your own pattern in bold
        titlePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        saveLabel = JLabel("Save A Pattern")
        boldFont = Font("Arial", Font.BOLD, 18)
        saveLabel.setFont(boldFont)
        saveLabel.setForeground(Color(255, 102, 0))
        titlePanel.add(saveLabel)
        configPanel.add(titlePanel)

        # Define bold font
        boldFont = Font("Arial", Font.BOLD, 12)
        severityPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        severityLabel = JLabel("Severity:")
        severityLabel.setFont(boldFont)
        severityPanel.add(severityLabel)
        configPanel.add(severityPanel)

        self.severityField = JComboBox(["Information", "Low", "Medium", "High"])
        configPanel.add(self.severityField)
        
       # Name title in bold
        namePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        nameLabel = JLabel("Name:")
        nameLabel.setFont(boldFont)
        namePanel.add(nameLabel)
        configPanel.add(namePanel)
        self.nameField = JTextArea()
        self.nameField.setPreferredSize(Dimension(200,30))
        self.nameField.setBorder(compoundBorder)
        configPanel.add(self.nameField)

        # Regex label
        self.regexPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.regexLabel = JLabel("Regex:")
        self.regexLabel.setFont(boldFont)
        self.regexPanel.add(self.regexLabel)
        configPanel.add(self.regexPanel)
        self.regexField = JTextArea()
        self.regexField.setBorder(compoundBorder)
        self.regexField.setPreferredSize(Dimension(900, 40))
        configPanel.add(self.regexField)

        # Button for adding new regex fields
        #self.addButton = JButton("+")
        #self.addButton.addActionListener(AddFieldActionListener(self.regexPanel))
        #self.regexPanel.add(self.addButton)

        # Description title in bold
        descriptionLabelPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        descriptionLabel = JLabel("Description:")
        descriptionLabel.setFont(boldFont)
        descriptionLabelPanel.add(descriptionLabel)
        configPanel.add(descriptionLabelPanel)
        self.descriptionField = JTextArea()
        self.descriptionField.setBorder(compoundBorder)
        self.descriptionField.setLineWrap(True)
        self.descriptionField.setWrapStyleWord(True) 
        configPanel.add(self.descriptionField)

        saveButton = JButton('Save', actionPerformed=self.saveConfig)
        configPanel.add(saveButton)

        return configPanel

    def getResponseHeadersAndBody(self, content):
        response = content.getResponse()
        response_info = self._helpers.analyzeResponse(response)
        headers = response_info.getHeaders()

        # Extract the body using Python bytearray from Java byte array
        response_body_bytes = response[response_info.getBodyOffset():]
        response_body = bytearray(response_body_bytes)

        # Decode the byte array to a string
        body = response_body.decode('utf-8', errors='ignore')
        return headers, body

    def loadRegexFile(self):
        try:
            with open("config.json", "r") as json_file:
                return json.load(json_file)
        except Exception as e:
            print("Failed to load config.json:", e)
            return []
        
    def saveConfig(self, event):
        # Collect regex patterns

        # Create new configuration object
        new_config = {
            "name": self.nameField.text,
            "active": True,
            "regex": [self.regexField.text],
            "severity": self.severityField.getSelectedItem(),
            "description": self.descriptionField.text
        }

        # Append new configuration and save to file
        self.regexJson.append(new_config)
        self.saveRegexFile()

        # Clear input fields
        self.severityField.setSelectedIndex(0)
        self.descriptionField.text = ""
        self.nameField.text = ""
        self.regexField.text = ""

        # Reload configuration and update UI
        self.regexJson = self.loadRegexFile()
        self.updateNameList()

    def saveRegexFile(self):
        try:
            with open("config.json", "w") as file:
                json.dump(self.regexJson, file, indent=4)
            print("Regex configuration saved successfully.")
        except Exception as e:
            print("Error saving regex configuration:", str(e))


    def updateCheckboxList(self):
        model = DefaultListModel()
        for obj in self.regexJson:
            checkbox = JCheckBox(obj["name"], selected=obj.get("active", False))
            model.addElement(checkbox)

        # Assuming self.nameList is the JList for the checkboxes
        self.nameList.setModel(model)
        self.nameList.repaint()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        response_bytes = messageInfo.getResponse()
        response = self._helpers.bytesToString(response_bytes)
        url = self._helpers.analyzeRequest(messageInfo).getUrl()

        for obj in self.regexJson:
            if obj.get("active", True):
                for pattern in obj["regex"]:
                    compiled_pattern = re.compile(pattern)
                    matches = list(re.finditer(compiled_pattern, response))
                    if matches:
                        offsets = [array('i', [match.start(), match.end()]) for match in matches]

                        # Apply the markers and create annotated messages
                        annotatedMessage = self._callbacks.applyMarkers(messageInfo, None, offsets)

                        # Create and report the issue
                        issue = CustomScanIssue(
                            httpService=messageInfo.getHttpService(),
                            url=url,
                            httpMessages=[annotatedMessage],
                            name=obj["name"],
                            severity=obj["severity"],
                            confidence="Tentative",
                            issueDetail=obj["description"]
                        )
                        self._callbacks.addScanIssue(issue)

    def charToByteOffset(self, response_bytes, char_offset):
        # Convert the substring up to char_offset into a string
        substring = self._helpers.bytesToString(response_bytes[:char_offset])
        # Get the byte length of this string
        byte_offset = len(substring.encode('utf-8'))
        return byte_offset

    # Then, in your updateNameList method, use the NonEditableTableModel subclass
    def createNameList(self):
        columnNames = ["Name", "Active"]
        tableModel = DefaultTableModel(columnNames, 0)

        # Instantiate your custom table model
        tableModel = NonEditableTableModel(columnNames, 0)
        tableModel.setColumnIdentifiers(columnNames)

        for obj in self.regexJson:
            name = obj["name"]
            active = "Yes" if obj["active"] else "No"
            tableModel.addRow([name, active])

        # Create the table with the model
        self.nameTable = JTable(tableModel)
        self.nameTable.setAutoCreateRowSorter(True)

        # Adjust column widths
        nameColumn = self.nameTable.getColumn("Name")
        activeColumn = self.nameTable.getColumn("Active")
        nameColumn.setPreferredWidth(200)
        activeColumn.setPreferredWidth(100)
        activeColumn.setMaxWidth(100)
        activeColumn.setMinWidth(50) 

        # Wrap the table in a scroll pane with vertical scrollbar only
        scrollPane = JScrollPane(self.nameTable, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)

        # Add a mouse listener to the table for interaction
        tableMouseListener = TableMouseListener(self)
        self.nameTable.addMouseListener(tableMouseListener)
        return scrollPane
    
    def updateNameList(self):
        # Column names for the table
        columnNames = ["Name", "Active"]

        # Create a new table model with the updated data
        updatedTableModel = DefaultTableModel(columnNames, 0)
        for obj in self.regexJson:
            name = obj["name"]
            active = "Yes" if obj["active"] else "No"
            updatedTableModel.addRow([name, active])

        # Set the new model to the nameTable
        self.nameTable.setModel(updatedTableModel)
    
# MouseListener updated for JTable
class TableMouseListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    def mouseClicked(self, event):
        row = self.extender.nameTable.getSelectedRow()
        if row >= 0:
            modelRow = self.extender.nameTable.convertRowIndexToModel(row)
            regexConfig = self.extender.regexJson[modelRow]

            # Update the checkbox state and reset its action listener
            self.extender.checkbox.setSelected(regexConfig["active"])
            self.updateCheckboxListener(regexConfig)

            # Update description text
            descriptionText = "Name:\n{}\n\nDescription:\n{}\n\nRegex Patterns:\n{}".format(
            regexConfig["name"], regexConfig["description"], '\n'.join(regexConfig["regex"]))
            self.extender.descriptionArea.setText(descriptionText)
            self.extender.updateNameList()

    def updateCheckboxListener(self, regexConfig):
        # Remove all existing action listeners to avoid duplicates
        for actionListener in self.extender.checkbox.getActionListeners():
            self.extender.checkbox.removeActionListener(actionListener)

        # Add the new action listener with the updated regexConfig
        self.extender.checkbox.addActionListener(CheckboxListener(regexConfig, self.extender))

class CheckboxListener(ActionListener):
    def __init__(self, obj, extender):
        self.obj = obj
        self.extender = extender

    def actionPerformed(self, event):
        checkbox = event.getSource()
        self.obj['active'] = checkbox.isSelected()
        print("Checkbox clicked for:", self.obj['name'], "New Active status:", self.obj['active'])
        self.extender.saveRegexFile()
        self.extender.updateNameList() 

class AddFieldActionListener(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        borderPadding = BorderFactory.createEmptyBorder(10, 10, 10, 10)
        borderOutline = BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1)
        compoundBorder = BorderFactory.createCompoundBorder(borderOutline, borderPadding)
        regexField = JTextArea()
        regexField.setPreferredSize(Dimension(700, 40)) 
        regexField.setBorder(compoundBorder)
        self.panel.add(regexField)
        self.panel.revalidate()

class ListCellRenderer(DefaultListCellRenderer):
    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        component = super(ListCellRenderer, self).getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
        return component
    
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, severity, confidence, issueDetail):
     
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._severity = severity
        self._confidence = confidence
        self._issueDetail = issueDetail

# Subclass DefaultTableModel to make table cells non-editable
class NonEditableTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        # This method ensures no cell can be edited
        return False

    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0 
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return self._confidence
    
    def getIssueBackground(self):
        return None 
    
    def getRemediationBackground(self):
        return None 
    
    def getIssueDetail(self):
        return self._issueDetail
    
    def getRemediationDetail(self):
        return None
    
    def getHttpMessages(self):
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService
    
    def getScanIssues(self, url):
        return None

# Instantiate the BurpExtender
if __name__ in ('__main__', '__console__'):
    BurpExtender()
