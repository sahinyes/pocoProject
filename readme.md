# PowerCoders Final Project

## Domain Enumeration & Scanning App  

![](static/togif.gif)

<!-- 
<img src="https://cdn-images-1.medium.com/max/800/1*o4oLY5BoTPLX-giVn0p6Hg.gif" height=400px width=800px> -->

## Description

This is my final project for Powercoders bootcamp. The Domain Enumeration and Scanning App is a Flask-based web application that provides a comprehensive solution for enumerating subdomains, checking the services running on each subdomain, scanning open ports, identifying vulnerabilities, and discovering available directories for a given domain.

By leveraging various scanning techniques, the app empowers users to gather valuable information about their target domain, helping them assess potential security risks, identify exposed services, and uncover potential entry points for attackers.

This is project produced by the [project discovery](https://github.com/projectdiscovery) tools. 

## Features

* Subdomain Enumeration: The app utilizes advanced techniques to discover subdomains associated with the target domain, providing a comprehensive list for further analysis.

* Service Checking: It performs a service check on each subdomain, identifying the specific services running on them. This information helps in understanding the technologies and potential attack vectors present.

* Port Scanning: Users can select specific subdomains to conduct port scanning. The app uses Nmap to scan for open ports on the chosen subdomains, revealing potential entry points or exposed services.

* Vulnerability Assessment: Leveraging the power of Nmap's vulnerability scanning capabilities, the app performs vulnerability assessments on the open ports, identifying potential security vulnerabilities that may exist within the scanned services.

* Directory Enumeration: The app also includes directory enumeration functionality using Dirb. It scans the selected subdomains and identifies accessible directories, helping users identify potential paths to sensitive information or hidden functionalities.

* User-Friendly Web Interface: The app provides a clean and intuitive web interface, allowing users to easily enter the target domain, select subdomains for scanning, and view the results in a structured and organized manner.

* Detailed Results: The app presents the scan results in a comprehensive manner, providing information about discovered subdomains, services running on each subdomain, open ports, identified vulnerabilities, and available directories. This allows users to quickly identify potential security risks and take appropriate actions.
