## Dependencies

- python (https://www.python.org/downloads/)
- Graphviz package (https://graphviz.org/download/)
- pandoc (https://pandoc.org/installing.html)

## How to use guide with screenshots

1. Provide your system model in the threatModel.py file. Existing elements such as ThreatModel, Server, DataStore, DataFlow, Boundary, or Actor can be imported and used to assist with model creation.

![image](https://user-images.githubusercontent.com/43823689/231517795-69fb913d-55b7-454c-87e3-8a95b82ce949.png)

2. Provide detailed properties to the elements to make the threat detection as accurate as possible.

![image](https://user-images.githubusercontent.com/43823689/231517842-ac2bafc4-bf10-4ff1-9790-72a462e08f17.png)

3. Run the tool using the bash command line. Run the run.sh script which will prompt for various options. Type A to generate the DFD diagram and B to generate the report.

![image](https://user-images.githubusercontent.com/43823689/231517877-026d6dcb-9dcf-45ea-8d99-5150d2e565f6.png)

4. The report will list all potential threats applicable to the system.

![image](https://user-images.githubusercontent.com/43823689/231517916-6e18f569-9083-4d1e-9d36-39ad7825b042.png)

5. Further details about the threat can be obtained by expanding it.

![image](https://user-images.githubusercontent.com/43823689/231517947-5eaad955-6192-47e1-89d2-9ba5bfb6fa16.png)

#### Dataflow Diagram generation inspired from PyTm https://github.com/izar/pytm

## Class Diagram



