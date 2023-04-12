#!/bin/bash

echo "Welcome to Threat Pilot"
echo "This tool assumes your system to description in the threatModel.py file"
echo "=================================================="
echo "Please enter A for creating the Data Flow Diagram"
echo "Please enter B for creating compresensive report"
echo "=================================================="

read input

if [ "$input" == "A" ]
then
    sed -i '1s/False/True/g' userInput.txt
    sed -i '2s/True/False/g' userInput.txt
    python ./threatModel.py | dot -Tpng -o dfd_diagram.png
    echo "dfd_diagram.png have been created/updated successfully"
elif [ "$input" == "B" ]
then
    sed -i '1s/True/False/g' userInput.txt
    sed -i '2s/False/True/g' userInput.txt
    python ./threatModel.py | pandoc -f markdown -t html > report.html
    echo "report.html have been created/updated successfully"
else
    echo "Invalid input. Please enter A or B."
fi