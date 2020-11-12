
Dependency Threat
=================



A Command Line tool to analyze the threat of npm dependency vulnerabilities through the history of your GitHub application.

* LICENSE: MIT license


CONCEPT
---------------------------------------------------------------------
The workflow of Dependency Threat tool goes as follows:

* Fetch the history of package.json file.
* Resolve dependency versions.
* Identify and classify the threat of dependency versions (based on the approach in this [study](https://arxiv.org/abs/2009.09019)).
* Generates a report as a csv file that contains the analysis, and html file that visualizes the report.


INSTALLATION
-----------------------
Dependency Threat is developed and tested mainly on GNU/Linux and Mac platforms. Thus it is very likely it will work out of the box
on any Linux-like and Mac platforms, upon providing the right requirements and version of Python.

**To install**, simply run:
```
pip3 install git+"https://github.com/mahmoud-alfadel/DependencyThreat"
```

USAGE
-----------
To understand the commands used by the tool, please run the following:
```
dependency_threat --help
```

Example
-----------
To help you use the tool, we show below an example of running the tool on a popular Node.js application called Wiki.js. We assume that the tool is already installed. We use the following command to run the tool:
```
dependency_threat -o report.csv -a c1efcdxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  https://github.com/Requarks/wiki
```
The previous command uses the three arguments:
* The first argument (optional) is the name & path of the output csv file. By default it will save in the current folder.
* The second argument (required) is Github Access Token, it is required to fetch the history of package.json file  in your repository. Please use your own GitHub token. see: https://github.com/settings/tokens.
* The URL of the GitHub repository.


Tool Output
-----------
The tool output  in the CLI looks like the following:

![alt text](https://raw.githubusercontent.com/mahmoud-alfadel/DependencyThreat/master/example/Fig1.pdf)

Generated Files
-----------
The tool generates two files: 
* CSV file that contains all the details of the threat levels of dependnecies in the project.
* HTML file that visulaizes some of the reported  figures  in the csv file with respect with threat levels of dependencies. The HTML file is generated by defualt even if the output csv file argument is not set.

![alt text](https://raw.githubusercontent.com/mahmoud-alfadel/DependencyThreat/master/example/report.pdf)
