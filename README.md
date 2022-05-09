# **Security in Computing: Secure Chat Platform**

## Student Info

| Name         | E-mail              |
|--------------|---------------------|
| Bram Silue   | bram.silue@vub.be   |
| Lars Willems | lars.willems@vub.be |

<br/>

## Table of Contents
1. [Introduction](##Introduction)
2. [How to run](##How-to-run)


<br/>

## Introduction
The purpose of this project is to create a secure chat platform similar to Slack, which allows users to communicate messages in channels or as private messages. 

We were provided a simple web-based Slack clone that contains the main functionality from Slack, although without any regards to security, both at client side and server side. 

The main requirement is to secure the implementation, limiting what data can be read by different parties (such as other users, or the server itself), and protecting it from common exploits.

<br/>

## How to run
The server for the chat platform is written in NodeJS, and uses Socket.IO for communication. The front-end itself is a simple web client utilizing jQuery, Bootstrap and Socket.IO.

First, make sure [*Node.JS*](https://nodejs.org/en/download/) and *Socket.IO* (for both [client](https://socket.io/docs/v4/client-installation/) and [server](https://socket.io/docs/v4/server-installation/)) are installed.

After that, run the application with the following commands:

```
$ cd Chat
$ npm install
$ npm start
```

Finally, browse to `http://localhost:3000` in a browser to see the chat application.
