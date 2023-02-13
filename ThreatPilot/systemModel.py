#!/usr/bin/env python3

from threatPilot import TM, Server, Datastore, Dataflow, Boundary, Actor

systemModel = TM("Simple system threat model")
systemModel.description = "This is a sample threat model of a very simple system. " \
                          "It consists of a Web-browser, web-server, database, and a trust boundary."

internet = Boundary("Internet")

user = Actor("Web-Browser")
user.inBoundary = internet

web = Server("Web Server")
web.OS = "Ubuntu"
web.isHardened = True
web.sanitizesInput = False
web.encodesOutput = True
web.authorizesSource = False

db = Datastore("SQL Database")
db.OS = "Ubuntu"
db.isHardened = False
db.isSQL = True
db.inScope = True

user_to_web = Dataflow(user, web, "Make a request")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = 'Some request'
user_to_web.order = 1

web_to_db = Dataflow(web, db, "View/Edit data")
web_to_db.protocol = "MySQL"
web_to_db.dstPort = 3306
web_to_db.data = 'some SQL data'
web_to_db.order = 2

db_to_web = Dataflow(db, web, "Get data")
db_to_web.protocol = "MySQL"
db_to_web.dstPort = 80
db_to_web.data = 'SQL query result'
db_to_web.order = 3

web_to_user = Dataflow(web, user, "Get Response")
web_to_user.protocol = "HTTP"
web_to_user.data = 'Web server gives response back to end user'
web_to_user.order = 4

systemModel.process()
