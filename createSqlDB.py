import sqlite3

size = 100

# Create a database in RAM
db = sqlite3.connect('threats.db')

# Get a cursor object
cursor = db.cursor()

query = f'''CREATE TABLE threats
                (sid varchar({size}) PRIMARY KEY NOT NULL,
                target varchar({size}) NOT NULL,
                description varchar({size}) NOT NULL,
                details varchar({size}) NOT NULL,
                severity varchar({size}) NOT NULL,
                condition varchar({size}) NOT NULL,
                prerequisites varchar({size}) NOT NULL,
                mitigations varchar({size}) NOT NULL,
                custexample varchar({size}) NOT NULL,
                custreferences varchar({size}) NOT NULL)'''

# Create a table
cursor.execute(query)

query = f'''
        INSERT INTO threats (sid, target, description, details, severity, condition, prerequisites, mitigations, custexample, custreferences)
        VALUES (
            "id1",
            "Server",
            "Server Side Include (SSI) Injection",
            "An attacker can use Server Side Include (SSI) Injection to send code to a web application that then gets executed by the web server. Doing so enables the attacker to achieve similar results to Cross Site Scripting, viz., arbitrary code execution and information disclosure, albeit on a more limited scale, since the SSI directives are nowhere near as powerful as a full-fledged scripting language. Nonetheless, the attacker can conveniently gain access to sensitive files, such as password files, and execute shell commands",
            "High",
            "targetType.isInputSanitized is False or targetType.isOutputEncoded is False",
            "A web eserver that supports server side includes and has them enabledUser controllable input that can carry include directives to the web server",
            "mitigation here",
            "example here",
            "https://capec.mitre.org/data/definitions/101.html"
        );'''
cursor.execute(query)

query = f'''
        INSERT INTO threats (sid, target, description, details, severity, condition, prerequisites, mitigations, custexample, custreferences)
        VALUES (
            "id2",
            "Server",
            "Server Side Include (SSI) Injection",
            "description 2",
            "High",
            "targetType.isInputSanitized is False and targetType.isOutputEncoded is False",
            "A web eserver that supports server side includes and has them enabledUser controllable input that can carry include directives to the web server",
            "mitigation here",
            "example here",
            "https://capec.mitre.org/data/definitions/101.html"
        );'''
cursor.execute(query)

query = f'''
        INSERT INTO threats (sid, target, description, details, severity, condition, prerequisites, mitigations, custexample, custreferences)
        VALUES (
            "id3",
            "Server",
            "Server Side Include (SSI) Injection",
            "description 3",
            "High",
            "targetType.isInputSanitized is False and targetType.isOutputEncoded is False",
            "A web eserver that supports server side includes and has them enabledUser controllable input that can carry include directives to the web server",
            "mitigation here",
            "example here",
            "https://capec.mitre.org/data/definitions/101.html"
        );
        '''

cursor.execute(query)

# Save (commit) the changes
db.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
db.close()