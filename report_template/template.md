<link href="app.css" rel="stylesheet"></link>

&nbsp;

- **System Name**: {tm.identifier}
- **Description**: {tm.summary}

&nbsp;

## Dataflow Diagram

![](dfd_diagram.png)

&nbsp;

## Dataflows
&nbsp;

Name|From|To |Data|Protocol|Port
|:----:|:----:|:---:|:----:|:--------:|:----:|
{dataflows:repeat:|{{item.identifier}}|{{item.source.identifier}}|{{item.destination.identifier}}|{{item.data}}|{{item.protocolSummary}}|{{item.destinationPort}}|
}

&nbsp;

## Potential Threats
&nbsp;
&nbsp;

|{findings:repeat:
<details>
  <summary>   {{item.threatSID}}   --   {{item.threatDescription}}</summary> 
  <div class="threat">
  <h4> Targeted Element </h4>
  <p> {{item.threatTarget}} </p>
  <h4> Severity </h4>
  <p>{{item.threatSeverity}}</p>
  <h4>Example Instances</h4>
  <p>{{item.threatExample}}</p>   
  <h4>Mitigations</h4>
  <p>{{item.threatMitigations}}</p>
  <h4>References</h4>
  <p>{{item.threatReferences}}</p> 
  </div>
  &nbsp;
  &nbsp;
  &emsp;      
</details>
}|

&nbsp;
&nbsp;
