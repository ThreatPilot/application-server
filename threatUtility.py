from hashlib import sha224
from re import sub, match
from threatTemplate import SuperFormatter
from weakref import WeakKeyDictionary
from sys import stderr, exit
import sqlite3
from os.path import dirname
import uuid

class UserInput:
    def __init__(self):
        pass

    def add(self, name, value):
        setattr(self, name, value)

user_input = None


class customInstance:
    def __init__(self, default_value, instance_type=None):
        self._default_value = default_value
        if instance_type is None:
            self._instance_type = type(default_value)
        else:
            self._instance_type = instance_type
        self._values = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self._values.get(instance, self._default_value)

    def __set__(self, instance, value):
        if not isinstance(value, self._instance_type):
            raise ValueError(f"{self._instance_type.__name__} value expected, got a {type(value).__name__}")
        self._values[instance] = value

class customBoundary:
    def __init__(self, default_value, ):
        self._default_value = default_value
        self._values = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self._values.get(instance, self._default_value)

    def __set__(self, instance, value):
        if not isinstance(value, Boundary):
            raise ValueError(f"Boundary value expected, got a {type(value).__name__}")
        self._values[instance] = value

class customElement:
    def __init__(self, default_value, ):
        self._default_value = default_value
        self._values = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self._values.get(instance, self._default_value)

    def __set__(self, instance, value):
        if not isinstance(value, Element):
            raise ValueError(f"Element value expected, got a {type(value).__name__}")
        self._values[instance] = value


def generate_unique_id(object):
    hash_string = str(object.identifier) + str(object.uuid)
    hash_object = sha224(hash_string.encode())
    hex_dig = hash_object.hexdigest()
    return sub(r'\d+', '', hex_dig)

def debug(args, msg):
    if args.debug is True:
        stderr.write("DEBUG: {}\n".format(msg))

class Threat():
    threatSID = customInstance("")
    threatDescription = customInstance("")
    threatDetails = customInstance("")
    threatSeverity = customInstance("")
    threatCondition = customInstance("")
    threatPrerequisites = customInstance("")
    threatMitigations = customInstance("")
    threatExample = customInstance("")
    threatReferences = customInstance("")
    threatTarget = []

    def __init__(self, threat):
        self.threatSID = threat[0]
        self.threatTarget = threat[1]
        self.threatDescription = threat[2]
        self.threatDetails = threat[3]
        self.threatSeverity = threat[4]
        self.threatCondition = threat[5]
        self.threatPrerequisites = threat[6]
        self.threatMitigations = threat[7]
        self.threatExample = threat[8]
        self.threatReferences = threat[9]
    
    def process(self, targetType):
        if (self.threatTarget is None):
            return None
        elif (type(self.threatTarget) == list) and (targetType.__class__.__name__ not in self.threatTarget):
            return None
        elif (type(self.threatTarget) != list) and (targetType.__class__.__name__ != self.threatTarget):
            return None
        result = eval(self.threatCondition)
        return result


class Finding():
    def __init__(self, name, threat):
        self.name = name
        self.threatSID = threat.threatSID
        self.threatDescription = threat.threatDescription
        self.threatDetails = threat.threatDetails
        self.threatSeverity = threat.threatSeverity
        self.threatMitigations = threat.threatMitigations
        self.threatExample = threat.threatExample
        self.threatReferences = threat.threatReferences
        self.threatTarget = threat.threatTarget

class ThreatModel():
    _flows = []
    _elements = []
    _threats = []
    _findings = []
    _boundaries = []
    _excluded_threats = []
    _superformatter = None
    summary = customInstance("")

    def __init__(self, identifier):
        self.identifier = identifier
        ThreatModel._superformatter = SuperFormatter()
        
        conn = sqlite3.connect('threats.db')
        c = conn.cursor()
        c.execute("SELECT * FROM threats")
        rows = c.fetchall()
        for row in rows:
            ThreatModel._threats.append(Threat(row))
        conn.close()

    def resolve_findings(self):
        for element in (ThreatModel._elements):
            if element.isInScope:
                for threat in ThreatModel._threats:
                    if threat.process(element):
                        ThreatModel._findings.append(Finding(element.identifier, threat))

    def validate(self):
        if self.summary is None:
            raise ValueError("Threat Model must have a description")
        for element in (ThreatModel._elements + ThreatModel._flows):
            element.validate()

    def draw_dfd(self):
        print("digraph tm {\n\tgraph [\n\tfontname = Calibri;\n\tfontsize = 14;\n\t]")
        print("\tnode [\n\tfontname = Calibri;\n\tfontsize = 14;\n\trankdir = lr;\n\t]")
        print("\tedge [\n\tshape = none;\n\tfontname = Calibri;\n\tfontsize = 12;\n\t]")
        print('\tlabelloc = "t";\n\tfontsize = 20;\n\tnodesep = 1;\n')
        for boundary in ThreatModel._boundaries:
            boundary.draw_dfd()
        for element in ThreatModel._elements:
            if type(element) != Boundary and element.isWithinBoundary is None:
                element.draw_dfd()
        print("}")

    def generate_report(self):
        result = get_user_input()
        ThreatModel._template = result.report
        with open(self._template) as file:
            template = file.read()
        print(ThreatModel._superformatter.format(template, tm=self, dataflows=ThreatModel._flows, threats=ThreatModel._threats,
                                                    elements=ThreatModel._elements, boundaries=ThreatModel._boundaries,
                                                    findings=ThreatModel._findings))
    
    def process(self):
        self.validate()
        result = get_user_input()
        if result.dfd:
            self.draw_dfd()
        if result.report:
            self.resolve_findings()
            self.generate_report()


class Element:
    identifier = customInstance("")
    summary = customInstance("")
    isWithinBoundary = customBoundary(None)
    isRestricted = customInstance(False)
    isInScope = customInstance(True)
    descriptionOS = customInstance("")
    isSourceAuthenticated = customInstance(False)
    isInputSanitized = customInstance(False)
    isOutputEncoded = customInstance(False)
    protocolSummary = customInstance("")
    isUsingSQL = customInstance(False)
    data = customInstance("")
    source = customElement(None)
    destination = customElement(None)
    destinationPort = customInstance(10000)
    flowOrder = customInstance(-1)
    flowName = customInstance("")

    def __init__(self, identifier):
        self.identifier = identifier
        self.uuid = uuid.uuid4()
        self._isDFDGenerated = False
        ThreatModel._elements.append(self)

    def validate(self):
        if self.identifier is None:
            raise ValueError("Element must have a name")
        if self.summary is None:
            raise ValueError("Element must have a summary")

    def draw_dfd(self):
        self._isDFDGenerated = True
        print("%s [\n\tshape = square;" % generate_unique_id(self))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{0}</b></td></tr></table>>;'.format(self.identifier))
        print("]")
    
    def set_color(self):
        if self.isInScope is True:
            return "black"
        else:
            return "grey69"

class Server(Element):
    def __init__(self, identifier):
        super().__init__(identifier)

    def draw_dfd(self):
        self._isDFDGenerated = True
        color = self.set_color()
        print("{0} [\n\tshape = circle\n\tcolor = {1}".format(generate_unique_id(self), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{}</b></td></tr></table>>;'.format(self.identifier))
        print("]")


class ExternalEntity(Element):
    def __init__(self, identifier):
        super().__init__(identifier)


class DataStore(Element):
    def __init__(self, identifier):
        super().__init__(identifier)

    def draw_dfd(self):
        self._isDFDGenerated = True
        color = self.set_color()
        print("{0} [\n\tshape = none;\n\tcolor = {1};".format(generate_unique_id(self), color))
        print('\tlabel = <<table sides="TB" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.identifier, color))
        print("]")


class Actor(Element):
    def __init__(self, identifier):
        super().__init__(identifier)

    def draw_dfd(self):
        self._isDFDGenerated = True
        print("%s [\n\tshape = square;" % generate_unique_id(self))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><b>{0}</b></td></tr></table>>;'.format(self.identifier))
        print("]")

class Process(Element):

    def __init__(self, identifier):
        super().__init__(identifier)

    def draw_dfd(self):
        self._isDFDGenerated = True
        color = self.set_color()
        print("{0} [\n\tshape = circle;\n\tcolor = {1};\n".format(generate_unique_id(self), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.identifier, color))
        print("]")


class SetOfProcesses(Process):
    def __init__(self, identifier):
        super().__init__(identifier)

    def draw_dfd(self):
        self._isDFDGenerated = True
        color = self.set_color()
        print("{0} [\n\tshape = doublecircle;\n\tcolor = {1};\n".format(generate_unique_id(self), color))
        print('\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.identifier, color))
        print("]")


class DataFlow(Element):
    def __init__(self, source, destination, flowName):
        self.source = source
        self.destination = destination
        self.flowName = flowName
        super().__init__(flowName)
        ThreatModel._flows.append(self)

    def __set__(self, instance, value):
        print("Should not have gotten here.")

    def validate(self):
        if self.source is None:
            raise ValueError("Source is None")
        if self.destination is None:
            raise ValueError("Destination is None")

    def draw_dfd(self):
        self._isDFDGenerated = True
        print("\t{0} -> {1} [".format(generate_unique_id(self.source), generate_unique_id(self.destination)))
        color = self.set_color()
        if self.flowOrder >= 0:
            print('\t\tcolor = {2};\n\t\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color="{2}"><b>({0}) {1}</b></font></td></tr></table>>;'.format(self.flowOrder, self.flowName, color))
        else:
            print('\t\tcolor = {1};\n\t\tlabel = <<table border="0" cellborder="0" cellpadding="2"><tr><td><font color ="{1}"><b>{0}</b></font></td></tr></table>>;'.format(self.flowName, color))
        print("\t]")


class Boundary(Element):
    def __init__(self, identifier):
        super().__init__(identifier)
        if identifier not in ThreatModel._boundaries:
            ThreatModel._boundaries.append(self)

    def draw_dfd(self):
        if self._isDFDGenerated:
            return

        self._isDFDGenerated = True
        print("subgraph cluster_{0} {{\n\tgraph [\n\t\tfontsize = 10;\n\t\tfontcolor = firebrick2;\n\t\tstyle = dashed;\n\t\tcolor = firebrick2;\n\t\tlabel = <<i>{1}</i>>;\n\t]\n".format(generate_unique_id(self), self.identifier))
        for element in ThreatModel._elements:
            if element.isWithinBoundary == self and not element._isDFDGenerated:
                element.draw_dfd()
        print("\n}\n")


def get_user_input():
    global user_input
    if user_input is not None:
        return user_input
    else:
        user_input = UserInput()
        file = open("userInput.txt", "r")
        lines = file.readlines()
        file.close()
        i = 0
        while i < len(lines):
            line = lines[i]
            values = line.split()
            if values[1] == "True":
                if len(values) == 2:
                    user_input.add(values[0], True)
                else:
                    user_input.add(values[0], values[2])
            else:
                user_input.add(values[0], False)
            i += 1
        return user_input