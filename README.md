# **Security in Computing: Chat platform with end-to-end encryption**
The purpose of this project is to create a **secure** chat platform similar to Slack, which allows users to communicate messages in channels or as private messages. 

## Student Info
| Name         | E-mail              |
|--------------|---------------------|
| Bram Silue   | bram.silue@vub.be   |
| Lars Willems | lars.willems@vub.be |


## Table of Contents
1. [Introduction](##Introduction)
2. [How to run](##How-to-run)


## Introduction
We were provided a simple web-based Slack clone that contains the main functionality from Slack, although without any regards to security, both at client side and server side. 

The main goal of this project is to secure the implementation, by limiting what data can be read by different parties (such as other users, or the server itself) and protecting it from common exploits.


## How to run
The server for the chat platform is written in NodeJS, and uses Socket.IO for communication. The front-end itself is a simple web client utilizing jQuery, Bootstrap and Socket.IO.

First, make sure to install:
- [NodeJS](https://nodejs.org/en/download/).
- Socket.IO, for both [client](https://socket.io/docs/v4/client-installation/) and [server](https://socket.io/docs/v4/server-installation/).

After that, run the application with the following commands:

```
$ cd Chat
$ npm install
$ npm start
```

Finally, browse to `http://localhost:3000` in a browser to see the chat application.
