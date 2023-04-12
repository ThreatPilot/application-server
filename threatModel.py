from threatUtility import ThreatModel, Server, DataStore, DataFlow, Boundary, Actor

system_model = ThreatModel("Simple system threat model")
system_model.summary = "This is a sample threat model of a very simple system. " \
                        "It consists of a Web-browser, web-server, database, and a trust boundary."

internet = Boundary("Internet")

web_browser = Actor("Web-Browser")
web_browser.isWithinBoundary = internet

web_server = Server("Web Server")
web_server.descriptionOS = "Ubuntu"
web_server.isRestricted = True
web_server.isInputSanitized = False
web_server.isOutputEncoded = True
web_server.isSourceAuthenticated = False

database = DataStore("SQL Database")
database.descriptionOS = "Ubuntu"
database.isRestricted = False
database.isUsingSQL = True
database.isInScope = True

web_browser_to_web_server = DataFlow(web_browser, web_server, "Make a request")
web_browser_to_web_server.protocolSummary = "HTTP"
web_browser_to_web_server.destinationPort = 80
web_browser_to_web_server.data = 'Some request'
web_browser_to_web_server.flowOrder = 1

web_server_to_database = DataFlow(web_server, database, "View/Edit data")
web_server_to_database.protocolSummary = "MySQL"
web_server_to_database.destinationPort = 3306
web_server_to_database.data = 'some SQL data'
web_server_to_database.flowOrder = 2

database_to_web_server = DataFlow(database, web_server, "Get data")
database_to_web_server.protocolSummary = "MySQL"
database_to_web_server.destinationPort = 80
database_to_web_server.data = 'SQL query result'
database_to_web_server.flowOrder = 3

web_server_to_web_browser = DataFlow(web_server, web_browser, "Get Response")
web_server_to_web_browser.protocolSummary = "HTTP"
web_server_to_web_browser.data = 'Web server gives response back to end user'
web_server_to_web_browser.flowOrder = 4

system_model.process()
