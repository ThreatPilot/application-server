## Useful Commands

1> create DFD diagram from system model

```python ./ThreatPilot/systemModel.py --dfd | dot -Tpng -o dfd_diagram.png```

2> create HTML report from system model

```python ./ThreatPilot/systemModel.py --report ./ThreatPilot/report_template/template.md | pandoc -f markdown -t html > report.html```

## Dependencies

- python version 3.7.0
- Graphviz package
- java 14.0.1
- pandoc