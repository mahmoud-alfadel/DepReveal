DepReveal
=================
![](https://badgen.net/badge/version/v0.0.1/red)
![](https://badgen.net/badge/python/3.5|3.6|3.7/blue)
![](https://badgen.net/badge/PRs/Welcome/green)
   
A tool to analyze the discoverability of npm dependency vulnerabilities in a GitHub project.

Concept
---------------------------------------------------------------------
The workflow of the tool goes as follows:

* Fetch the history of the package.json file.
* Resolve dependency versions.
* Identify and classify the discoverability levels of vulnerable dependency versions (based on the approach in our study).
* Generates a CSV file that contains the analysis and HTML file that visualizes the analysis.

Installation
-----------------------
The command-line version of the tool is developed and tested mainly on GNU/Linux and Mac platforms. Thus it is very likely it will work out of the box
on any Linux-like and Mac platforms upon providing the right requirements and version of Python and Git.

**To install**, simply run:
```
pip3 install git+"https://github.com/AnonymousName/DepReveal/"
```

Usage
-----------
To understand the commands used by the tool, please run the following:
```
dependency_reveal --help
```

Example
-----------
To help you use the tool, we show below an example of running the tool on a popular Node.js project called *React-native* from Facebook. We assume that the tool is already installed. We use the following command to run the tool:
```
dependency_reveal -o report.csv https://github.com/facebook/react-native
```
The previous command uses the two arguments:
* The first argument (optional) is the name & path of the generated CSV file. By default, it will save in your current folder.
* The second argument (required) is the URL of the project GitHub repository. Note 

Tool Output
-----------
The tool generates two files: 
* CSV file that contains all details about the discoverability levels of dependencies throughout the entire project lifetime (in days).
* HTML file that illustrates historical analytical report for the discoverability levels of the vulnerable dependencies in the project. The HTML file is generated by default even if the output CSV file argument is not set. The HTML file contains the following 4 different reports:
    - **Dependency Discoverability Graph**: it shows the history of discoverability levels of the project dependencies.

    - **Discoverability Levels Frequency**: it shows the frequency of dependency vulnerabilities per discoverability level. Using the configuration bar available at the top right-side corner of the plot, the user can zoom in/out, enable/disable one of the levels that appear on the legends of the plot.

    - **Period of Package Discoverability (in days)**: it show the period of time in which a vulnerable dependency had been affecting the application, per discoverability level. Users can also enable/disable one of the discoverability levels by clicking on the legends of the plot.

    - **Package Versions Discoverability**: it shows what package versions account for the vulnerable dependencies.

The generated HTML report for the *React-native* project can be seen [here](https://bit.ly/3xkUxZk).

Web-UI
-----------
We provide a [Web-UI](https://bit.ly/3emg5w3) for the tool to facilitate its usage.

**LICENSE**
-----------
Released under the [MIT License](https://opensource.org/licenses/mit-license.php).

---
