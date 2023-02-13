<link href="C:\Users\Tejash\Desktop\application-server\ThreatPilot\report_template\app.css" rel="stylesheet"></link>

&nbsp;

- **System Name**: {tm.name}
- **Description**: {tm.description}

&nbsp;

## Dataflow Diagram

![](dfd_diagram.png)

&nbsp;

## Dataflows
&nbsp;

Name|From|To |Data|Protocol|Port
|:----:|:----:|:---:|:----:|:--------:|:----:|
{dataflows:repeat:|{{item.name}}|{{item.source.name}}|{{item.sink.name}}|{{item.data}}|{{item.protocol}}|{{item.dstPort}}|
}

&nbsp;

## Potential Threats
&nbsp;
&nbsp;

|{findings:repeat:
<details>
  <summary>   {{item.id}}   --   {{item.description}}</summary> 
  <div class="threat">
  <h4> Targeted Element </h4>
  <p> {{item.target}} </p>
  <h4> Severity </h4>
  <p>{{item.severity}}</p>
  <h4>Example Instances</h4>
  <p>{{item.example}}</p>   
  <h4>Mitigations</h4>
  <p>{{item.mitigations}}</p>
  <h4>References</h4>
  <p>{{item.references}}</p> 
  </div>
  &nbsp;
  &nbsp;
  &emsp;      
</details>
}|

&nbsp;
&nbsp;
